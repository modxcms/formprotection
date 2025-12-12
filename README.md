# Form Protection for MODX

## Overview
Form Protection provides enhanced spam protection for your FormIt forms. It combines multiple spam prevention techniques to block automated submissions and spam attacks without inconveniencing legitimate users.

Requires: MODX Revolution and FormIt

## Features
- **Time-based token validation**: Block form submissions that happen too quickly (likely bots)
- **Content filtering**: Block submissions containing spam keywords or patterns
- **Email validation**: Prevent submissions from known spam email domains
- **Rate limiting**: Prevent multiple submissions within a short time frame
- **No CAPTCHA required**: Less friction for legitimate users
- **Fully configurable**: Customize all aspects of the protection

## Installation
1. Install via the MODX Package Manager.
2. Set up the system setting `formit.spam_time_secret` with a unique key (optional but recommended).

## Quick Start
1. Add the `generateTimeTokenHook` as a preHook in your FormIt call.
2. Add the `formProtectionHook` to your hooks chain.
3. Add a hidden input field to your form for the time token.
4. Configure the spam protection settings as needed.

```html
[[!FormIt?
  &preHooks=`generateTimeTokenHook`
  &hooks=`formProtectionHook,email,redirect`
  &spamTimeThreshold=`5`
  &spamWordPatterns=`viagra,crypto,free offer`
  &spamEmailPatterns=`.ru,spammer.com`
  &rateLimit=`1`
  &rateLimitSeconds=`30`
  &rateLimitCookieName=`threshold_token`
  &rateLimitMaxSubmissions=`10`
  &rateLimitSubmissionInterval=`3600`
  &spamRedirectResourceId=`123`
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
   - Checking that the time token is valid.
   - Ensuring the form wasn't submitted too quickly.
   - Scanning all text fields for spam content patterns.
   - Validating email addresses against known spam patterns.
   - Enforcing rate limiting to prevent multiple submissions in a short time frame.
   - **Redirecting suspected spammers** to a specified resource ID if `spamRedirectResourceId` is set.

### Redirecting Suspected Spammers

The `spamRedirectResourceId` property allows you to redirect suspected spammers to a specific resource ID (e.g., a custom "Access Denied" or "Spam Detected" page). This property is optional and can be configured as follows:

- **Property**: `spamRedirectResourceId`
- **Description**: Resource ID of the page to redirect suspected spammers to. If not set or invalid, no redirection occurs. The "submitted too fast" error does not trigger a redirect.
- **Default**: `""` (no redirection)

#### Example Usage

```markdown
[[!FormIt?
  &preHooks=`generateTimeTokenHook`
  &hooks=`formProtectionHook,email`
  &spamRedirectResourceId=`123`
]]
```

## Configuration Options

### System Settings
- `formit.spam_time_secret` - Secret key used for token generation (default: "changeme").

### Hook Properties

#### formProtectionHook
| Property                  | Description                                      | Default                                   |
|---------------------------|--------------------------------------------------|-------------------------------------------|
| spamEmailField            | Field name for email address                    | "email"                                   |
| spamWordPatterns          | Comma-separated list of spam words/patterns     | "viagra,porn,sex,shit,fuck,bit.ly,youtube,free,optimization,CRM,bitcoin,crypto,ericjones" |
| spamEmailPatterns         | Comma-separated list of spam email patterns     | "order-fulfillment.net,bestlocaldata.com,.ru" |
| spamTimeField             | Field name for time token                       | "form_time_token"                         |
| spamTimeThreshold         | Minimum seconds before form submission is allowed | 7                                       |
| spamContentErrorMessage   | Error message for spam content detection        | "Your input contains words that are not allowed. Please revise your text and try again." |
| spamEmailErrorMessage     | Error message for spam email detection          | "The email address you entered appears invalid or flagged. Please use a valid email address." |
| timeTokenErrorMessage     | Error message for invalid time token            | "There was an issue with your session. Please refresh the page and try submitting the form again." |
| timeThresholdErrorMessage | Error message for form submitted too fast       | "You submitted the form unusually quickly. Please wait a few seconds and try again." |
| rateLimit                 | Enable or disable rate limiting                 | true                                     |
| rateLimitSeconds          | Seconds to wait before allowing another submission | 30                                      |
| rateLimitActionKey        | Unique action key for rate limiting             | "formProtection"                         |
| rateLimitCookieName       | Name of the cookie used for rate limiting       | "submission"                             |
| formId                    | Optional form ID for unique rate limiting per form | ""                                      |
| rateLimitErrorMessage     | Error message for exceeding rate limit          | "You just submitted this form successfully. Please wait a while before submitting again." |
| rateLimitMaxSubmissions   | Maximum number of submissions allowed within the timeframe | 5                                       |
| rateLimitSubmissionInterval | Timeframe (in seconds) for counting submissions | 86400 (1 day)                           |
| rateLimitMaxSubmissionsErrorMessage | Error message for exceeding max submissions | "You have reached the maximum number of submissions allowed. Please try again later." |
| spamRedirectResourceId    | Resource ID of the page to redirect suspected spammers to. If not set or invalid, no redirection occurs. The "submitted too fast" error does not trigger a redirect. | "" |

#### generateTimeTokenHook
| Property                  | Description                                      | Default                                   |
|---------------------------|--------------------------------------------------|-------------------------------------------|
| spamTimeSessionKey        | Session key used to store the time token         | "form_time_token"                         |

## Security Considerations
- Always change the default `formit.spam_time_secret` value to something unique.
- The time threshold is a balance between security and user experience; 5-10 seconds is usually optimal.
- Regularly update your spam patterns based on the spam you receive.
- Consider hiding error messages in production to avoid giving feedback to spammers.
- The rate limiter enforces a garbage collection threshold of 1 day for temporary files and limits the total number of files to 1000. These values are hardcoded and not configurable.

## Troubleshooting
- If legitimate users can't submit forms, try decreasing the `spamTimeThreshold`.
- If you're getting false positives, review and update your spam word patterns.
- Check your MODX error logs for detailed information about blocked submissions.

## Support
For assistance or to report issues, please contact:
- Email: jay@modx.com
- MODX Community Forums: https://community.modx.com
- GitHub: https://github.com/modxcms/formprotection/