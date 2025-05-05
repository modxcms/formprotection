# Form Protection for MODX

## Overview
Form Protection provides enhanced spam protection for your FormIt forms. It combines multiple spam prevention techniques to block automated submissions and spam attacks without inconveniencing legitimate users.
 
Requires: MODX Revolution, FormIt

## Features
- **Time-based token validation**: Block form submissions that happen too quickly (likely bots)
- **Content filtering**: Block submissions containing spam keywords or patterns
- **Email validation**: Prevent submissions from known spam email domains
- **No CAPTCHA required**: Less friction for legitimate users
- **Fully configurable**: Customize all aspects of the protection

## Installation
1. Download the Form Protection package from the MODX Package Manager
2. Install via the MODX Package Manager
3. Set up the system setting `formit.spam_time_secret` with a unique key (optional but recommended)

## Quick Start
1. Add the `generateTimeTokenHook` as a preHook in your FormIt call
2. Add the `formProtectionHook` to your hooks chain
3. Add a hidden input field to your form for the time token
4. Configure the spam protection settings as needed

```html
[[!FormIt?
  &preHooks=`generateTimeTokenHook`
  &hooks=`formProtectionHook,email,redirect`
  &spamTimeThreshold=`5`
  &spamWordPatterns=`viagra,crypto,free offer`
  &spamEmailPatterns=`.ru,spammer.com`
]]

<form action="[[~[[*id]]]]" method="post">
  <!-- Your form fields here -->
  <input type="hidden" name="form_time_token" value="[[!+fi.form_time_token]]">
  <button type="submit">Submit</button>
</form>
```

## How It Works
Form Protection uses a two-hook approach to validate submissions:

1. `generateTimeTokenHook` (preHook): Creates a time-based token that includes a timestamp and a secure hash.
2. `formProtectionHook` (hook): Validates the submission by:
   - Checking that the time token is valid
   - Ensuring the form wasn't submitted too quickly
   - Scanning all text fields for spam content patterns
   - Validating email addresses against known spam patterns

## Configuration Options

### System Settings
- `formit.spam_time_secret` - Secret key used for token generation (default: "changeme")

### Hook Properties

#### formProtectionHook
| Property | Description | Default |
|----------|-------------|---------|
| spamEmailField | Field name for email address | "email" |
| spamWordPatterns | Comma-separated list of spam words/patterns | "viagra,porn,sex,shit,fuck,bit.ly,youtube,free,optimization,CRM,bitcoin,crypto,ericjones" |
| spamEmailPatterns | Comma-separated list of spam email patterns | "ericjones,order-fulfillment.net,bestlocaldata.com,.ru,getpeople.io" |
| spamTimeField | Field name for time token | "form_time_token" |
| spamTimeThreshold | Minimum seconds before form submission is allowed | 7 |
| spamContentErrorMessage | Error message for spam content detection | "Input picked up as spam." |
| spamEmailErrorMessage | Error message for spam email detection | "Email picked up as spam." |
| timeTokenErrorMessage | Error message for invalid time token | "Invalid time token." |
| timeThresholdErrorMessage | Error message for form submitted too fast | "Form submitted too fast. Please wait a moment." |

#### generateTimeTokenHook
No configurable properties. Uses the system setting `formit.spam_time_secret`.

## Security Considerations
- Always change the default `formit.spam_time_secret` value to something unique
- The time threshold is a balance between security and user experience; 5-10 seconds is usually optimal
- Regularly update your spam patterns based on the spam you receive
- Consider hiding error messages in production to avoid giving feedback to spammers

## Troubleshooting
- If legitimate users can't submit forms, try decreasing the `spamTimeThreshold`
- If you're getting false positives, review and update your spam word patterns
- Check your MODX error logs for detailed information about blocked submissions

## Support
For assistance or to report issues, please contact:
- Email: jay@modx.com
- MODX Community Forums: https://community.modx.com
- GitHub: https://github.com/modxcms/formprotection/