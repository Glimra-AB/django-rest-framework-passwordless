from drfpasswordless.utils import (
    create_callback_token_for_user,
    send_email_with_callback_token,
    send_sms_with_callback_token
)


class TokenService(object):
    @staticmethod
    def send_token(user, alias_type, **message_payload):
        token = create_callback_token_for_user(user, alias_type)
        send_action = None
        if alias_type == 'email':
            send_action = send_email_with_callback_token

        elif alias_type == 'mobile':
            can_login, error_code = user.can_login_with_mobile()
            if can_login:
                send_action = send_sms_with_callback_token
            else:
                return False, error_code
        # Send to alias
        return user.send_action(alias_type, send_action, token, **message_payload)
