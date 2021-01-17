# AWS SecretManager LOGIN secret key
LOGIN_INFO_SECRET_NAME = 'xxxxxx/login-information'
# login url
LOGIN_TARGET_URL = 'https://1234567890.signin.aws.amazon.com/console'
# login page check element
LOGIN_LOCATION = 'accountFields'

# AWS SecretManager MFA secret key
MFA_SECRET_NAME = 'xxxxxx/mfa/secret-key'
MFA_SECRET_KEY = 'mfa-secret-key'
# mfa page check element
MFA_PAGE_LOCATION = 'mfaHeaderMessage'

# AWS SecretManager slack bot api key 
SLACK_BOT_SECRET_NAME = 'xxxxxxx/slackbot/token'
SLACK_BOT_SECRET_KEY = 'slack-bot-token'

# console page(after login) check element
CONSOLE_LOCATION = "//*[@id='content']/div/h1/span[1]"

# dashboard page(after login) url
DASHBOARD_URL = 'https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=default-dashuboard;start=P1D'
# dashboard page(after login) check element
DASHBOARD_LOCATION = 'react-select-4--value-item'
