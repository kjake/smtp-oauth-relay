import asyncio
import logging
from email import policy
from email.parser import BytesParser

from aiosmtpd.smtp import MISSING

import addressing
import config
import config_resolver
import graph_client
import message_utils
import remap
import sslContext
from auth import Authenticator
from custom import CustomController


class Handler:
    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        if not addressing.is_valid_smtp_mailbox(address, allow_null=True):
            logging.warning("Rejected malformed MAIL FROM address: %s", address)
            return "553 5.1.3 Error: malformed address"
        return MISSING

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if not addressing.is_valid_smtp_mailbox(address, allow_null=False):
            logging.warning("Rejected malformed RCPT TO address: %s", address)
            return "553 5.1.3 Error: malformed address"
        return MISSING

    async def handle_DATA(self, server, session, envelope):
        try:
            logging.info(f"Message from {envelope.mail_from} to {envelope.rcpt_tos}")

            if not hasattr(session, 'access_token'):
                logging.error("No access token available in session")
                return "530 5.7.0 Authentication required"

            raw_message = envelope.content
            rfc5322_error = message_utils.validate_rfc5322_message(raw_message)
            if rfc5322_error:
                logging.error("RFC 5322 validation failed: %s", rfc5322_error)
                return rfc5322_error

            parsed_message = BytesParser(policy=policy.SMTP).parsebytes(raw_message)
            x_sender_raw = parsed_message.get('X-Sender')
            x_sender_address = addressing.parse_email_address(x_sender_raw)

            return_path_address = addressing.parse_email_address(parsed_message.get('Return-Path'))
            from_header_raw = parsed_message.get('From')
            from_header_address = addressing.parse_email_address(from_header_raw)
            envelope_from_address = addressing.parse_email_address(envelope.mail_from)
            header_updates: dict[str, str | None] = {}
            header_change_reasons: list[str] = []

            if x_sender_raw is not None and not x_sender_address:
                replacement_sender = return_path_address or from_header_address
                if replacement_sender:
                    header_updates['X-Sender'] = replacement_sender
                    x_sender_address = replacement_sender
                    header_change_reasons.append("normalized invalid X-Sender")

            from_email = (
                x_sender_address
                or return_path_address
                or from_header_address
                or envelope_from_address
            )

            domain_context = config_resolver.resolve_domain_context(
                x_sender_raw,
                parsed_message.get('Return-Path'),
                from_header_raw,
                envelope.mail_from,
                *(envelope.rcpt_tos or [])
            )
            domain_hint = domain_context.domain
            settings = domain_context.settings

            recipient_header_updates = remap.remap_recipient_headers(parsed_message)
            if recipient_header_updates:
                header_updates.update(recipient_header_updates)
                logging.info("Remapped recipient headers based on TO remap settings.")
                header_change_reasons.append("remapped recipient headers")
            if envelope.rcpt_tos:
                remapped_recipients = remap.remap_recipient_list(envelope.rcpt_tos)
                if remapped_recipients != envelope.rcpt_tos:
                    envelope.rcpt_tos = remapped_recipients
                    logging.info("Remapped SMTP recipients based on TO remap settings.")

            if not from_email:
                failback_address = domain_context.failback_address
                if failback_address:
                    logging.warning(
                        "Using failback sender address for malformed message (domain hint: %s)",
                        domain_hint
                    )
                    from_email = failback_address
                    header_updates['From'] = failback_address
                    if not addressing.parse_email_address(parsed_message.get('X-Sender')):
                        header_updates['X-Sender'] = failback_address
                    header_change_reasons.append("applied failback sender")
                else:
                    logging.error("Unable to determine sender address and no failback configured.")
                    return "554 Transaction failed"

            if domain_hint and from_header_raw and remap.is_remap_enabled(
                domain_hint,
                settings,
                from_header_address
            ):
                failback_address = domain_context.failback_address
                if failback_address:
                    header_updates['From'] = failback_address
                    header_updates['Reply-To'] = message_utils.build_reply_to_value(
                        parsed_message.get('Reply-To'),
                        from_header_raw
                    )
                    from_email = failback_address
                    logging.info(
                        "Remapped From header for domain %s using failback address %s",
                        domain_hint,
                        failback_address
                    )
                    header_change_reasons.append("remapped From header")
                else:
                    logging.warning(
                        "From remapping requested for domain %s but no failback address is "
                        "configured",
                        domain_hint,
                    )

            if session.lookup_from_email:
                # Some clients won't let you set a from address independent of the auth user.
                # Issue: #36
                # replace from header in envelope if lookup_from_email is set
                header_updates['From'] = session.lookup_from_email
                from_email = session.lookup_from_email
                header_change_reasons.append("overrode From header from lookup user")

            if header_updates:
                if logging.getLogger().isEnabledFor(logging.DEBUG):
                    for header_name in sorted(header_updates.keys()):
                        old_value = parsed_message.get(header_name)
                        new_value = header_updates[header_name]
                        if new_value is None:
                            logging.debug(
                                "Header update: %s removed (was %r)",
                                header_name,
                                old_value
                            )
                        else:
                            logging.debug(
                                "Header update: %s %r -> %r",
                                header_name,
                                old_value,
                                new_value
                            )
                logging.info(
                    "Message headers updated: %s; reasons=%s",
                    ", ".join(sorted(header_updates.keys())),
                    ", ".join(header_change_reasons) if header_change_reasons else "unspecified"
                )
                raw_message = message_utils.update_raw_headers(raw_message, header_updates)

            # Send email using Microsoft Graph API
            success, error_detail, status_code = graph_client.send_email(
                session.access_token,
                raw_message,
                from_email
            )

            if success:
                return "250 OK"
            failure_notification = domain_context.failure_notification
            if failure_notification:
                notification_sender = domain_context.failback_address or from_email
                if notification_sender:
                    graph_client.send_failure_notification(
                        access_token=session.access_token,
                        from_email=notification_sender,
                        notification_address=failure_notification,
                        parsed_message=parsed_message,
                        envelope=envelope,
                        error_detail=error_detail
                    )
                else:
                    logging.warning(
                        "Failure notification configured for domain %s but no sender address is "
                        "available",
                        domain_hint,
                    )
            await asyncio.sleep(0.5)
            if status_code == 404:
                return "551 User not local"
            return "451 Action aborted"

        except Exception as e:
            logging.exception(f"Error handling DATA command: {str(e)}")
            return "554 Transaction failed"


# noinspection PyShadowingNames
async def amain():
    match config.TLS_SOURCE:
        case 'file':
            context = sslContext.from_file(config.TLS_CERT_FILEPATH, config.TLS_KEY_FILEPATH)
            logging.info(f"Loaded certificate from file: {config.TLS_CERT_FILEPATH}")

        case 'keyvault':
            if not config.AZURE_KEY_VAULT_URL or not config.AZURE_KEY_VAULT_CERT_NAME:
                logging.error(
                    "Azure Key Vault URL and Certificate Name must be set when "
                    "TLS_SOURCE is 'keyvault'"
                )
                raise ValueError("Azure Key Vault URL and Certificate Name must be set")
            context = sslContext.from_keyvault(
                config.AZURE_KEY_VAULT_URL,
                config.AZURE_KEY_VAULT_CERT_NAME
            )
            logging.info(
                "Loaded certificate from Azure Key Vault: %s",
                config.AZURE_KEY_VAULT_CERT_NAME
            )

        case 'off':
            context = None

        case _:
            logging.error(f"Invalid TLS_SOURCE: {config.TLS_SOURCE}")
            raise ValueError(f"Invalid TLS_SOURCE: {config.TLS_SOURCE}")

    # Configure TLS cipher suite if specified
    if context:
        if config.TLS_CIPHER_SUITE:
            context.set_ciphers(config.TLS_CIPHER_SUITE)

        cipher_names = ", ".join([cipher["name"] for cipher in context.get_ciphers()])
        logging.info("TLS cipher suites used: %s", cipher_names)

    controller = None
    try:
        controller = CustomController(
            Handler(),
            hostname='',  # bind dual-stack on all interfaces
            port=8025,
            ident=config.SERVER_GREETING,
            authenticator=Authenticator(),
            auth_required=True,
            auth_require_tls=config.REQUIRE_TLS,
            require_starttls=config.REQUIRE_TLS,
            tls_context=context
        )
        controller.start()
        logging.info("SMTP OAuth relay server started on port 8025")
    except Exception as e:
        logging.exception(f"Failed to start SMTP server: {str(e)}")
        if controller:
            controller.stop()
        raise


if __name__ == '__main__':
    # Setup logging
    logging.basicConfig(
        level=config.LOG_LEVEL,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Run main function
    try:
        loop.create_task(amain())
        loop.run_forever()
    except KeyboardInterrupt:
        logging.info("Shutdown requested via keyboard interrupt")
    except Exception as e:
        logging.exception(f"Unexpected error: {str(e)}")
    finally:
        logging.info("Shutting down...")
        tasks = asyncio.all_tasks(loop)
        for task in tasks:
            task.cancel()
        loop.close()
