"""Explainable detection for common outbound-email fraud and phishing patterns.

A category is emitted only when related indicators form a meaningful pattern.
Strong combinations are confirmed HIGH/CRITICAL findings and therefore enter
OMG's existing RESTRICTED decision path. Single weak words are not sufficient.
"""
from __future__ import annotations
import re
from bs4 import BeautifulSoup

SCAM_CATEGORIES = [
    "ADVANCE_FEE_SCAM", "LOTTERY_SCAM", "FAKE_GIVEAWAY_SCAM",
    "TAX_REFUND_PHISHING", "LOAN_SCAM", "FINANCIAL_FRAUD",
    "IDENTITY_THEFT", "PERSONAL_INFORMATION_HARVESTING",
    "CREDENTIAL_HARVESTING", "URGENCY_MANIPULATION", "REWARD_DECEPTION",
    "INVESTMENT_SCAM", "CRYPTOCURRENCY_SCAM", "ROMANCE_SCAM",
    "JOB_FEE_SCAM", "FAKE_DONATION_SCAM", "INVOICE_PAYMENT_FRAUD",
    "BUSINESS_EMAIL_COMPROMISE", "CEO_IMPERSONATION", "VENDOR_IMPERSONATION",
    "ACCOUNT_TAKEOVER", "ACCOUNT_SUSPENSION_PHISHING", "DELIVERY_FEE_SCAM",
    "SUBSCRIPTION_RENEWAL_PHISHING", "TECH_SUPPORT_SCAM", "GIFT_CARD_SCAM",
    "EXTORTION_SCAM", "SEXTORTION_SCAM", "QR_CODE_PHISHING",
    "MFA_CODE_HARVESTING", "PAYMENT_REDIRECTION", "BANKING_PHISHING",
    "FAKE_INHERITANCE_SCAM", "UNSOLICITED_PROMOTIONAL_SPAM",
    "FAKE_INVOICE_FRAUD",
    "FAKE_PURCHASE_ORDER",
    "FAKE_REFUND_CLAIM",
    "PAYMENT_OVERDUE_PRESSURE",
    "PAYMENT_SPLITTING_REQUEST",
    "FAKE_TAX_COMPLIANCE_NOTICE",
    "FAKE_LEGAL_THREAT",
    "FAKE_ACCOUNT_SUSPENSION",
    "FAKE_SECURITY_ALERT",
    "FAKE_CUSTOMER_SUPPORT",
    "FAKE_RECRUITER_IMPERSONATION",
    "FAKE_JOB_OFFER",
    "FAKE_INTERVIEW_FEE",
    "FAKE_BUSINESS_PARTNERSHIP",
    "FAKE_CRYPTO_AIRDROP",
    "FAKE_INVESTMENT_RETURN",
    "PONZI_SCHEME_PROMOTION",
    "PUMP_AND_DUMP_PROMOTION",
    "FAKE_GOVERNMENT_AUTHORITY",
    "FAKE_COURT_SUMMONS",
    "FAKE_INSURANCE_CLAIM",
    "FAKE_DELIVERY_CUSTOMS_FEE",
    "MONEY_MULE_RECRUITMENT",
    "MONEY_LAUNDERING_INSTRUCTION",
    "PAYMENT_APPROVAL_BYPASS",
    "MFA_PUSH_FATIGUE",
    "FAKE_SSO_LOGIN",
    "FAKE_VPN_LOGIN",
    "FAKE_CLOUD_STORAGE_LOGIN",
    "FAKE_WEBMAIL_LOGIN",
    "PASSWORD_MANAGER_PHISHING",
    "ACCOUNT_RECOVERY_ABUSE",
    "FAKE_EMAIL_QUARANTINE_NOTICE",
    "FAKE_EMAIL_DELIVERY_FAILURE",
    "HTML_FORM_CREDENTIAL_CAPTURE",
    "FAKE_PASSWORD_MANAGER_SHARING",
    "PAYROLL_DIRECT_DEPOSIT_CHANGE",
    "FAKE_AUDITOR_REQUEST",
    "FAKE_BOARD_MEMBER_REQUEST",
    "PAYMENT_BENEFICIARY_MISMATCH",
    "UNUSUAL_PAYMENT_DESTINATION",
    "CUSTOMER_PII_DISCLOSURE",
    "EMPLOYEE_PII_DISCLOSURE",
    "PAYMENT_CARD_DATA_EXPOSURE",
    "BANKING_INFORMATION_EXPOSURE",
    "HEALTH_INFORMATION_DISCLOSURE",
    "INTELLECTUAL_PROPERTY_EXFILTRATION",
    "SOURCE_CODE_EXFILTRATION",
    "BULK_DATA_TRANSFER",
    "EXTERNAL_STORAGE_EXFILTRATION",
    "PERSONAL_EMAIL_EXFILTRATION",
    "DATA_RETENTION_POLICY_BYPASS",
    "AUDIT_LOG_TAMPERING",
    "REMOTE_ACCESS_INSTALLATION",
    "MALICIOUS_MACRO_ENABLEMENT",
    "SENSITIVE_DATA_REQUEST",
    "UNAUTHORIZED_PRIVILEGE_ESCALATION",
    "DATA_DELETION_OR_DESTRUCTION",
    "SECURITY_CONTROL_DISABLEMENT",
]


def _has(pattern: str, text: str) -> bool:
    return bool(re.search(pattern, text, re.I | re.S))


def _text(subject: str, body: str, html: str) -> str:
    visible = BeautifulSoup("\n".join((body or "", html or "")), "html.parser").get_text(" ", strip=True)
    # Include href destinations as evidence; they are separately checked by URL module.
    soup = BeautifulSoup(html or "", "html.parser")
    hrefs = " ".join(str(a.get("href", "")) for a in soup.find_all("a", href=True))
    return re.sub(r"\s+", " ", f"{subject or ''} {visible} {hrefs}")[:150_000]


def inspect_fraud_patterns(subject: str, body: str = "", html: str = "") -> list[dict]:
    t = _text(subject, body, html)
    if not t.strip():
        return []

    # Educational/security-awareness messages should not be treated as live lures.
    awareness = _has(
        r"\b(?:security awareness|phishing awareness|scam awareness|fraud prevention|"
        r"how to (?:spot|recognize|report|avoid) (?:a )?(?:scam|phishing)|"
        r"example of (?:a )?(?:phishing|scam|fraud))\b", t
    )

    findings: list[dict] = []
    seen: set[str] = set()

    def add(code: str, severity: str, message: str, *, confirmed: bool = True, confidence: float = 0.94):
        if code in seen:
            return
        seen.add(code)
        findings.append({
            "code": code,
            "category": code,
            "severity": severity,
            "confidence": confidence,
            "confirmed": confirmed,
            "message": message,
        })

    if awareness:
        return findings

    # Shared evidence primitives.
    prize = _has(r"\b(?:voucher|gift\s*card|prize|reward|giveaway|sweepstakes|lottery|winner|won|selected|promotional campaign)\b", t)
    winner = _has(r"\b(?:you have been selected|you(?:'| a)?ve been selected|you have won|congratulations|dear winner|exclusive reward|won an?)\b", t)
    advance_fee = _has(r"\b(?:activation|processing|administrative|release|handling|registration|verification|delivery|customs?)\s+fee\b|\bupfront\s+(?:payment|fee|charge)\b|\bpay\b.{0,100}\b(?:fee|charge)\b", t)
    unlock_or_release = _has(r"\b(?:unlock|activate|release|claim|collect|receive|disburse|process)\b", t)
    sensitive_request = _has(r"\b(?:submit|provide|send|upload|enter|share)\b.{0,220}\b(?:personal information|bank(?:ing)? (?:information|details|account)|account number|routing number|payment details|credit card|debit card|identity documents?|proof of identity|passport|national id|aadhaar|aadhar|pan card|date of birth|residential address|phone number)\b", t)
    urgency = _has(r"\b(?:within\s+\d+\s+hours?|\d+\s+hours?\s+only|today only|expires? today|immediately|urgent(?:ly)?|final notice|last chance|only\s+\d+\s+(?:remaining|left)|limited time)\b", t)
    money = _has(r"(?:[$€£₹]\s?\d[\d,]*(?:\.\d{2})?|\b\d[\d,]*(?:\.\d{2})?\s?(?:usd|dollars?|euros?|pounds?)\b)", t)

    # 1) Prize / voucher / lottery / giveaway + fee to unlock or receive.
    if prize and (winner or _has(r"\bfree\b.{0,50}\b(?:voucher|gift\s*card|prize|reward)\b", t)) and advance_fee and unlock_or_release:
        add("ADVANCE_FEE_SCAM", "CRITICAL", "A promised prize, voucher or reward is conditional on paying an activation, processing or release fee.")
        add("REWARD_DECEPTION", "HIGH", "A high-value reward claim is paired with a payment condition.", confirmed=False, confidence=0.4)
        if _has(r"\b(?:lottery|sweepstakes|jackpot|raffle)\b", t):
            add("LOTTERY_SCAM", "CRITICAL", "A lottery or prize-winning claim requires an advance payment.")
        else:
            add("FAKE_GIVEAWAY_SCAM", "HIGH", "A promotional giveaway or voucher claim requires an advance payment.", confirmed=False, confidence=0.4)

    # 2) Fake prize/gift claim + request for payment or personal data.
    if prize and winner and sensitive_request:
        if _has(r"\b(?:gift\s*card|smartphone|iphone|phone)\b", t):
            add("FAKE_GIVEAWAY_SCAM", "CRITICAL", "An unsolicited gift or device award requests sensitive recipient information.")
        add("PERSONAL_INFORMATION_HARVESTING", "HIGH", "A purported prize or giveaway requests personal, identity or financial information.", confirmed=False, confidence=0.4)
        add("IDENTITY_THEFT", "HIGH", "Identity or financial data is requested as a condition of receiving an unsolicited reward.", confirmed=False, confidence=0.4)

    # 3) Tax refund impersonation.
    tax = _has(r"\b(?:tax refund|taxpayer refund|tax rebate|revenue department|tax authority|irs|hmrc)\b", t)
    refund = _has(r"\b(?:refund|rebate)\b", t)
    bank_or_id = _has(r"\b(?:bank(?:ing)? (?:information|details|account)|account number|routing number|identification documents?|identity documents?|passport|national id|aadhaar|aadhar|pan (?:card|number)|personal information)\b", t)
    verify_or_submit = _has(r"\b(?:verify|verification|submit|provide|update|confirm|upload)\b", t)
    if tax and refund and bank_or_id and verify_or_submit:
        add("TAX_REFUND_PHISHING", "CRITICAL", "A tax-refund message requests banking or identity information to release a claimed refund.")
        add("BANKING_PHISHING", "HIGH", "A refund-themed message requests sensitive banking information.", confirmed=False, confidence=0.4)
        add("IDENTITY_THEFT", "HIGH", "A tax-refund pretext is used to solicit identity information.", confirmed=False, confidence=0.4)
        add("PERSONAL_INFORMATION_HARVESTING", "HIGH", "Personal or financial information is requested under a tax-refund pretext.", confirmed=False, confidence=0.4)
    elif refund and bank_or_id and urgency and verify_or_submit:
        add("FINANCIAL_FRAUD", "HIGH", "An urgent refund message requests sensitive banking or identity data.")

    # 4) Advance-fee loan fraud.
    loan = _has(r"\b(?:loan|credit|cash advance|personal loan|financing)\b", t)
    loan_promise = _has(r"\b(?:pre[- ]?approved|guaranteed approval|instant approval|100\s*%\s*guaranteed|approved regardless|no credit check)\b", t)
    loan_fee = advance_fee or _has(r"\b(?:pay|deposit|transfer|send)\b.{0,80}\b(?:processing|insurance|release|application|upfront)\s+fee\b", t)
    if loan and loan_promise and loan_fee:
        add("LOAN_SCAM", "CRITICAL", "A guaranteed or no-check loan approval is conditional on an upfront fee.")
        add("ADVANCE_FEE_SCAM", "HIGH", "An upfront fee is demanded before a promised loan is released.", confirmed=False, confidence=0.4)
        add("FINANCIAL_FRAUD", "HIGH", "The loan offer uses an upfront payment condition and unrealistic approval claims.", confirmed=False, confidence=0.4)
    elif loan and loan_promise and _has(r"\b(?:no employment verification|no paperwork|regardless of your financial history)\b", t):
        add("LOAN_SCAM", "HIGH", "A loan offer makes implausible guaranteed-approval claims while bypassing normal checks.")

    # 5) Credential/account takeover and MFA theft.
    credentials = _has(r"\b(?:password|login credentials?|username|otp|one[- ]time (?:password|code)|verification code|mfa code|2fa code|authentication code)\b", t)
    credential_action = _has(r"\b(?:submit|enter|provide|share|send|reply with|verify|confirm)\b", t)
    account_pressure = _has(r"\b(?:account|mailbox|profile|online banking|wallet)\b.{0,80}\b(?:suspend|lock|disable|close|restrict|expire|verify)\b|\b(?:suspend|lock|disable|close)\b.{0,60}\baccount\b", t)
    if credentials and credential_action and (account_pressure or urgency or _has(r"\b(?:click|visit|open)\b.{0,60}\b(?:link|button|portal|page)\b", t)):
        add("CREDENTIAL_HARVESTING", "CRITICAL", "The message requests authentication secrets using an account-verification or urgency pretext.")
        add("ACCOUNT_TAKEOVER", "HIGH", "Credentials or one-time authentication codes are solicited in a suspicious message.")
        if _has(r"\b(?:otp|one[- ]time (?:password|code)|mfa code|2fa code|verification code)\b", t):
            add("MFA_CODE_HARVESTING", "CRITICAL", "A one-time or multi-factor authentication code is requested.")
    if account_pressure and (urgency or _has(r"\b(?:verify|confirm|update)\b", t)) and _has(r"\b(?:click|link|login|sign in|password|credentials?)\b", t):
        add("ACCOUNT_SUSPENSION_PHISHING", "HIGH", "An account suspension or verification threat is used to drive a login or link action.")

    # 6) Invoice / supplier / executive impersonation and payment redirection.
    payment = _has(r"\b(?:invoice|payment|wire transfer|bank transfer|remittance|purchase order|vendor payment|supplier payment)\b", t)
    changed_bank = _has(r"\b(?:new|updated|changed|revised|replacement)\b.{0,70}\b(?:bank|account|payment)\b.{0,50}\b(?:details|information|instructions|number)\b|\b(?:bank|account|payment)\b.{0,60}\b(?:details|information)\b.{0,40}\b(?:changed|updated|new)\b", t)
    payment_action = _has(r"\b(?:pay|transfer|wire|send|remit|settle)\b", t)
    if payment and changed_bank and payment_action:
        add("PAYMENT_REDIRECTION", "CRITICAL", "Payment instructions or bank details are changed and the recipient is asked to transfer funds.")
        add("INVOICE_PAYMENT_FRAUD", "HIGH", "An invoice or payment workflow contains changed banking instructions.")
        add("BUSINESS_EMAIL_COMPROMISE", "HIGH", "The message exhibits a supplier or business-payment redirection pattern.")
    executive = _has(r"\b(?:ceo|chief executive|managing director|finance director|cfo|company director)\b", t)
    secrecy = _has(r"\b(?:keep this confidential|do not tell|don't tell|secret|discreetly|without informing)\b", t)
    if executive and payment_action and (urgency or secrecy):
        add("CEO_IMPERSONATION", "HIGH", "An executive identity is invoked to pressure an urgent or secret payment.")
        add("BUSINESS_EMAIL_COMPROMISE", "HIGH", "The message resembles executive impersonation or business-email-compromise fraud.")

    # 7) Delivery/customs fee lures.
    delivery = _has(r"\b(?:parcel|package|shipment|delivery|courier|customs)\b", t)
    delivery_fee = _has(r"\b(?:delivery|redelivery|customs|handling)\s+fee\b|\bpay\b.{0,70}\b(?:delivery|customs)\s+fee\b", t)
    if delivery and delivery_fee and (urgency or _has(r"\b(?:track|release|deliver|reschedule)\b", t)):
        add("DELIVERY_FEE_SCAM", "HIGH", "A parcel or delivery notice demands an unexpected fee to release or reschedule delivery.")
        add("ADVANCE_FEE_SCAM", "HIGH", "A payment is demanded before a promised delivery service is completed.")

    # 8) Employment/job fee fraud.
    job = _has(r"\b(?:job offer|work from home|remote position|vacancy|recruitment|hiring|employment opportunity|you are hired|job placement)\b", t)
    job_fee = _has(r"\b(?:registration|training|equipment|interview|placement|processing)\s+fee\b", t)
    if job and job_fee and _has(r"\b(?:pay|deposit|transfer|purchase)\b", t):
        add("JOB_FEE_SCAM", "HIGH", "An employment opportunity requires an upfront recruitment, training or equipment payment.")
        add("ADVANCE_FEE_SCAM", "HIGH", "An upfront payment is tied to a promised job or employment benefit.")

    # 9) Investment / crypto scams.
    investment = _has(r"\b(?:investment|invest|crypto(?:currency)?|bitcoin|ethereum|trading platform|forex)\b", t)
    guaranteed_returns = _has(r"\b(?:guaranteed|risk[- ]free|no risk)\b.{0,80}\b(?:profit|returns?|income|earnings?)\b|\b(?:profit|returns?|income)\b.{0,50}\bguaranteed\b", t)
    if investment and guaranteed_returns and (urgency or _has(r"\b(?:deposit|send|transfer|wallet address|connect wallet)\b", t)):
        add("INVESTMENT_SCAM", "CRITICAL", "An investment offer promises guaranteed returns and pressures the recipient to act or transfer funds.")
        if _has(r"\b(?:crypto|bitcoin|ethereum|wallet)\b", t):
            add("CRYPTOCURRENCY_SCAM", "HIGH", "A cryptocurrency-related offer uses guaranteed-return or urgent-funding claims.")
        add("FINANCIAL_FRAUD", "HIGH", "The investment message contains high-risk financial solicitation indicators.")

    # 10) Extortion/sextortion.
    extortion = _has(r"\b(?:pay|send|transfer)\b.{0,100}\b(?:or else|otherwise|unless)\b|\b(?:ransom|blackmail|extort)\b", t)
    threat = _has(r"\b(?:i have your (?:password|data|photos|videos)|i will (?:expose|publish|leak|share)|we will expose)\b", t)
    intimate = _has(r"\b(?:intimate photos?|private photos?|explicit videos?|webcam footage|nudes?)\b", t)
    if extortion and threat:
        add("EXTORTION_SCAM", "CRITICAL", "The message threatens exposure or harm unless money is paid.")
        if intimate:
            add("SEXTORTION_SCAM", "CRITICAL", "The extortion threat involves intimate images or sexual material.")

    # 11) Subscription renewal / tech-support lures.
    subscription = _has(r"\b(?:subscription|membership|renewal|billing plan)\b", t)
    if subscription and _has(r"\b(?:payment failed|renewal failed|cancel immediately|call support|refund)\b", t) and _has(r"\b(?:click|call|provide|update|verify)\b", t):
        add("SUBSCRIPTION_RENEWAL_PHISHING", "HIGH", "A subscription or renewal notice pushes the recipient to click, call or disclose payment information.")
    tech = _has(r"\b(?:technical support|tech support|microsoft support|apple support|computer infected|virus detected|device compromised)\b", t)
    if tech and _has(r"\b(?:call|pay|install|download|grant remote|remote access)\b", t):
        add("TECH_SUPPORT_SCAM", "HIGH", "A technical-support warning asks the recipient to pay, install software or grant remote access.")

    # 12) Charity / donation pretext.
    charity = _has(r"\b(?:charity|donation|disaster relief|humanitarian aid|fundraiser|救援)\b", t)
    if charity and _has(r"\b(?:urgent|emergency|victims|relief)\b", t) and _has(r"\b(?:wire|transfer|crypto|wallet|send money|donate now)\b", t):
        add("FAKE_DONATION_SCAM", "HIGH", "An urgent charitable appeal requests direct or difficult-to-reverse payments without verified context.")

    # 12b) Inheritance, romance, vendor and gift-card payment scams.
    inheritance = _has(r"\b(?:inheritance|inherited funds|estate funds|unclaimed inheritance|next of kin|beneficiary)\b", t)
    if inheritance and advance_fee and (sensitive_request or unlock_or_release):
        add("FAKE_INHERITANCE_SCAM", "CRITICAL", "An alleged inheritance or estate payment requires an advance fee or sensitive information.")
        add("ADVANCE_FEE_SCAM", "CRITICAL", "A fee is demanded before alleged inheritance funds are released.")

    romance = _has(r"\b(?:online relationship|dating|romantic partner|lover|i love you|soulmate)\b", t)
    romance_emergency = _has(r"\b(?:emergency|hospital|stranded|stuck abroad|customs|visa|ticket|medical bills?)\b", t)
    romance_payment = _has(r"\b(?:send|transfer|wire|pay|buy)\b.{0,80}\b(?:money|cash|gift cards?|bitcoin|crypto|ticket|fee)\b", t)
    if romance and romance_emergency and romance_payment:
        add("ROMANCE_SCAM", "CRITICAL", "A relationship or romantic pretext is combined with an emergency story and a request for money or gift cards.")
        add("ADVANCE_FEE_SCAM", "HIGH", "Payment is requested to resolve a claimed personal emergency.")

    gift_payment = _has(r"\b(?:buy|purchase|send|pay with|pay using)\b.{0,70}\b(?:gift cards?|itunes cards?|google play cards?|steam cards?)\b", t)
    gift_code = _has(r"\b(?:send|share|read|provide|reveal)\b.{0,60}\b(?:gift card|redemption)\s*(?:code|number)s?\b", t)
    if gift_payment or gift_code:
        add("GIFT_CARD_SCAM", "HIGH", "The recipient is instructed to pay with gift cards or disclose redemption codes.")
        if urgency or secrecy:
            add("FINANCIAL_FRAUD", "HIGH", "Gift-card payment instructions are paired with pressure or secrecy.")

    vendor_context = _has(r"\b(?:vendor|supplier|accounts payable|purchase order|invoice)\b", t)
    if vendor_context and changed_bank and payment_action:
        add("VENDOR_IMPERSONATION", "HIGH", "A vendor or supplier payment context contains changed bank details and a payment instruction.")

    qr_prompt = _has(r"\b(?:scan|open)\b.{0,45}\b(?:qr code|qr)\b|\bqr code\b.{0,60}\b(?:login|verify|payment|account|credentials?)\b", t)
    if qr_prompt and (credentials or account_pressure or payment_action):
        add("QR_CODE_PHISHING", "HIGH", "A QR-code action is connected to login, account verification or payment activity.")

    
    # 13) Generic unsolicited bulk/promotional spam is a review signal,
    # not an automatic block.
    promo_discount = _has(
        r"\b(?:\d{1,3}\s?%\s*(?:off|discount)|"
        r"(?:save|up to)\s+\d{1,3}\s?%|"
        r"discount|sale|deal|offer|savings|clearance)\b",
        t,
    )

    promo_campaign = _has(
        r"\b(?:exclusive savings|exclusive offer|special offer|"
        r"limited[- ]time offer|biggest sale|seasonal sale|"
        r"flash sale|promotional offer|special pricing)\b",
        t,
    )

    promo_cta = _has(
        r"\b(?:shop now|buy now|claim your deal|claim your offer|"
        r"grab yours|get yours|redeem now|order now|"
        r"shop today|browse deals|don't miss out)\b",
        t,
    )

    promo_urgency = _has(
        r"\b(?:today only|ends today|ends soon|limited time|"
        r"last chance|act now|hurry|while stocks last|"
        r"offer expires|only for today)\b",
        t,
    )

    bulk_promo = (
        (promo_discount and (promo_cta or promo_urgency))
        or (promo_campaign and (promo_cta or promo_urgency))
    )

    if bulk_promo and not (prize and advance_fee):
        add(
            "UNSOLICITED_PROMOTIONAL_SPAM",
            "MEDIUM",
            "The message combines promotional claims with urgency or a purchase/claim action; sender consent and reputation should be checked.",
            confirmed=False,
            confidence=0.55,
        )

    # 14) Fake work-from-home and unrealistic income opportunities.
    income_claim = _has(
        r"\b(?:earn|earning|make|making|get paid|income|salary)\b"
        r".{0,100}\b(?:₹|rs\.?|inr)?\s*[\d,]+"
        r"(?:\s*(?:per|a|every)\s*(?:day|week|month))?\b",
        t,
    )
    unrealistic_income = _has(
        r"\b(?:no experience required|no experience needed|"
        r"work from home|earn from home|guaranteed income|"
        r"easy money|passive income|daily income|weekly income)\b",
        t,
    )
    recruitment_action = _has(
        r"\b(?:register now|apply now|join now|secure your position|"
        r"limited positions|start earning|sign up now)\b",
        t,
    )
    if income_claim and unrealistic_income and recruitment_action:
        add("UNVERIFIED_INCOME_OPPORTUNITY", "MEDIUM",
            "An income opportunity combines an earnings claim, low-entry requirements and a recruitment action.",
            confirmed=False, confidence=0.65)

    # 15) Task-based earning and fake online jobs.
    task_earning = _has(
        r"\b(?:complete|finish|perform)\b.{0,60}\b(?:tasks?|assignments?|offers?)\b",
        t,
    )
    task_payment = _has(
        r"\b(?:earn|receive|get paid|payment|commission)\b.{0,70}\b(?:per task|daily|weekly|commission|reward|bonus)\b",
        t,
    )
    if task_earning and task_payment and _has(
        r"\b(?:telegram|whatsapp|online job|part.time job|"
        r"work from home|easy income)\b", t
    ):
        add("TASK_EARNING_SCAM", "MEDIUM",
            "An online task opportunity promises earnings for completing tasks; verify the employer and payment conditions.",
            confirmed=False, confidence=0.65)

    # 16) Fake survey and review earning schemes.
    survey = _has(r"\b(?:paid surveys?|product reviews?|app reviews?|"
                  r"like and subscribe|review and earn)\b", t)
    survey_reward = _has(r"\b(?:earn|cash reward|payment|"
                         r"commission|gift voucher|paid)\b", t)
    if survey and survey_reward:
        add("FAKE_SURVEY_REWARD_PROMOTION", "MEDIUM",
            "A survey or review activity promises financial rewards; verify the organization and terms.",
            confirmed=False, confidence=0.60)

    # 17) Referral and recruitment reward abuse.
    referral = _has(r"\b(?:refer|invite|recruit)\b.{0,60}\b(?:friends?|members?|people|users?)\b", t)
    referral_reward = _has(r"\b(?:earn|bonus|commission|cash reward|"
                           r"unlimited income|unlock reward)\b", t)
    if referral and referral_reward:
        add("REFERRAL_REWARD_ABUSE", "MEDIUM",
            "A referral campaign offers financial incentives for recruiting additional participants.",
            confirmed=False, confidence=0.55)

    # 18) Pyramid and multi-level marketing warning.
    pyramid = _has(
        r"\b(?:build your team|recruit your team|"
        r"earn from your downline|multiple income levels|"
        r"unlimited commissions|network marketing)\b", t
    )
    if pyramid and _has(r"\b(?:recruit|join|invest|membership|commission)\b", t):
        add("PYRAMID_SCHEME_INDICATOR", "HIGH",
            "The message contains recruitment-based income indicators requiring business-model verification.",
            confirmed=False, confidence=0.70)

    # 19) Fake free-trial and subscription promotions.
    free_trial = _has(r"\b(?:free trial|free subscription|"
                      r"try free|first month free)\b", t)
    automatic_charge = _has(r"\b(?:automatically charge|auto.?renew|"
                            r"recurring billing|subscription fee|"
                            r"charged after trial)\b", t)
    if free_trial and automatic_charge:
        add("DECEPTIVE_SUBSCRIPTION_PROMOTION", "MEDIUM",
            "A free-trial promotion includes automatic or recurring charges that require clear disclosure.",
            confirmed=False, confidence=0.60)

    # 20) Generic mailbox and password-reset phishing.
    mailbox = _has(r"\b(?:mailbox|email account|office 365|microsoft 365|"
                   r"webmail|google workspace)\b", t)
    login_action = _has(r"\b(?:sign in|log in|login|authenticate|"
                        r"access your account|click here)\b", t)
    if mailbox and login_action and (urgency or account_pressure):
        add("MAILBOX_PHISHING", "HIGH",
            "A mailbox access request uses urgency or account pressure to drive authentication.",
            confirmed=False, confidence=0.75)

    # 21)OAuth application consent phishing.
    oauth = _has(r"\b(?:oauth|authorize this application|"
                 r"grant permissions|consent request|"
                 r"allow access to your mailbox)\b", t)
    if oauth and _has(r"\b(?:email|mailbox|files|contacts|account|"
                      r"permissions|access)\b", t):
        add("OAUTH_CONSENT_PHISHING", "HIGH",
            "An application requests account or mailbox permissions that should be verified.",
            confirmed=False, confidence=0.75)

    # 22)Fake HR and payroll information requests.
    hr = _has(r"\b(?:human resources|hr department|payroll|"
              r"employee benefits|employee records)\b", t)
    employee_data = _has(r"\b(?:update|confirm|verify|submit|provide)\b.{0,100}"
                         r"\b(?:salary account|bank details|employee id|"
                         r"personal details|tax information)\b", t)
    if hr and employee_data:
        add("HR_PAYROLL_PHISHING", "HIGH",
            "An HR or payroll communication requests sensitive employee information.",
            confirmed=False, confidence=0.75)

    # 23) Fake shared-document notifications.
    shared_document = _has(r"\b(?:shared a document|shared file|"
                           r"view document|document awaiting review|"
                           r"secure document)\b", t)
    if shared_document and login_action and _has(
        r"\b(?:password|credentials|verify|sign in|account)\b", t
    ):
        add("SHARED_DOCUMENT_PHISHING", "HIGH",
            "A shared-document notification requests account authentication.",
            confirmed=False, confidence=0.75)

    # 24) Session expiration and reauthentication lures.
    session = _has(r"\b(?:session expired|session timeout|"
                   r"reauthenticate|session validation)\b", t)
    if session and login_action:
        add("SESSION_HIJACKING_PHISHING", "HIGH",
            "A session-expiration message directs the recipient to authenticate again.",
            confirmed=False, confidence=0.70)

        # 25) Fake employment equipment purchases.
    equipment_job = _has(r"\b(?:remote job|work from home|job offer|"
                         r"employment opportunity|new employee)\b", t)
    equipment_payment = _has(r"\b(?:purchase|buy|pay for|deposit)\b.{0,80}"
                             r"\b(?:laptop|computer|equipment|software|"
                             r"workstation|office supplies)\b", t)
    if equipment_job and equipment_payment:
        add("EMPLOYMENT_EQUIPMENT_SCAM", "HIGH",
            "An employment opportunity requires the recipient to purchase equipment or make a payment.",
            confirmed=False, confidence=0.75)

    # 26) Fake bank KYC requests.
    kyc = _has(r"\b(?:kyc update|complete kyc|kyc verification|"
               r"bank verification|account reactivation)\b", t)
    if kyc and (sensitive_request or credentials or account_pressure):
        add("BANK_KYC_PHISHING", "HIGH",
            "A bank verification request is combined with sensitive-data or credential collection.",
            confirmed=False, confidence=0.75)

    # 27) Fake overpayment and payment confirmation.
    overpayment = _has(r"\b(?:overpaid|excess payment|extra payment|"
                       r"paid twice|payment sent in error)\b", t)
    refund_action = _has(r"\b(?:refund|return|send back|transfer back|"
                         r"reimburse)\b", t)
    if overpayment and refund_action:
        add("OVERPAYMENT_REFUND_SCAM", "HIGH",
            "An alleged overpayment is followed by a request to return money.",
            confirmed=False, confidence=0.75)

    # 28)Fake cryptocurrency mining.
    mining = _has(r"\b(?:crypto mining|mining investment|cloud mining|"
                  r"mining package)\b", t)
    mining_return = _has(r"\b(?:guaranteed returns|daily profit|"
                         r"fixed income|risk.free profit)\b", t)
    if mining and mining_return:
        add("CRYPTO_MINING_SCAM", "HIGH",
            "A cryptocurrency mining offer promises guaranteed or fixed financial returns.",
            confirmed=False, confidence=0.75)

    # 29) Requests to disclose confidential business information.
    confidential = _has(
        r"\b(?:confidential|internal use only|restricted document|"
        r"proprietary information|trade secret|internal database)\b", t
    )
    disclosure = _has(
        r"\b(?:forward|send|upload|share|export|copy|transfer)\b.{0,100}"
        r"\b(?:external|personal email|third party|public link|"
        r"outside the company)\b", t
    )
    if confidential and disclosure:
        add("CONFIDENTIAL_DATA_DISCLOSURE", "HIGH",
            "The message combines confidential business information with an external disclosure action.",
            confirmed=False, confidence=0.75)

    # 30) Possible secrets in outbound email content.
    secret_assignment = _has(
        r"\b(?:api[_ -]?key|access[_ -]?token|secret[_ -]?key|"
        r"private[_ -]?key|client[_ -]?secret|password)\b"
        r"\s*[:=]\s*\S{6,}", t
    )
    if secret_assignment:
        add("POSSIBLE_CREDENTIAL_LEAKAGE", "HIGH",
            "The message appears to contain a credential or secret assignment; verify before sending.",
            confirmed=False, confidence=0.80)

    # 31) Hidden or suspicious HTML elements.
    if html:
        hidden_html = _has(
            r"display\s*:\s*none|visibility\s*:\s*hidden|"
            r"opacity\s*:\s*0|font-size\s*:\s*0", html
        )
        if hidden_html:
            add("HIDDEN_HTML_CONTENT", "MEDIUM",
                "The email contains hidden HTML content that should be inspected.",
                confirmed=False, confidence=0.65)

    # 32)Obfuscated or suspicious script references.
    if html and _has(r"<script\b|javascript\s*:|onerror\s*=|"
                     r"onload\s*=", html):
        add("SUSPICIOUS_HTML_SCRIPT", "HIGH",
            "The email HTML contains script-related constructs requiring inspection.",
            confirmed=False, confidence=0.80)


    # 33) Guaranteed website traffic and unrealistic marketing claims.
    traffic_claim = _has(
        r"\b(?:website traffic|website visitors|visitors|targeted customers)\b", t
    )
    traffic_promise = _has(
        r"\b(?:guaranteed|instantly|overnight|immediate results|"
        r"100,?000|thousands of)\b", t
    )
    traffic_service = _has(
        r"\b(?:traffic growth service|growth service|"
        r"promotional packages|marketing packages)\b", t
    )
    if traffic_claim and traffic_promise and traffic_service:
        add("UNSOLICITED_TRAFFIC_PROMOTION", "MEDIUM",
            "The message promotes guaranteed or instant website traffic growth.",
            confirmed=False, confidence=0.70)

    # 34) Free premium membership with an artificial deadline.
    free_membership = _has(
        r"\b(?:free|absolutely free|complimentary)\b.{0,80}"
        r"\b(?:premium membership|premium account|lifetime membership)\b", t
    )
    membership_deadline = _has(
        r"\b(?:expires tonight|expires today|before midnight|"
        r"expires in \d+ hours?|limited time)\b", t
    )
    if free_membership and membership_deadline:
        add("DECEPTIVE_FREE_MEMBERSHIP", "MEDIUM",
            "A free premium membership offer uses an expiry or urgency claim.",
            confirmed=False, confidence=0.65)

    # 35) Unsolicited advertising partnership requesting contact details.
    advertising_offer = _has(
        r"\b(?:advertising partnership|promotional campaign|"
        r"targeted customers|marketing partnership)\b", t
    )
    contact_request = _has(
        r"\b(?:reply with|send us|provide|share)\b.{0,80}"
        r"\b(?:contact details|contact information|business details)\b", t
    )
    if advertising_offer and contact_request:
        add("UNSOLICITED_ADVERTISING_SOLICITATION", "MEDIUM",
            "An advertising offer requests contact information to activate a promotional campaign.",
            confirmed=False, confidence=0.65)

    # 36) Fake lucky-number and promotional selection.
    lucky_selection = _has(
        r"\b(?:lucky number|selected in our promotional giveaway|"
        r"your number has been selected|number has been chosen)\b", t
    )
    selection_action = _has(
        r"\b(?:confirm your participation|claim your reward|"
        r"collect your prize|redeem your reward)\b", t
    )
    selection_deadline = _has(
        r"\b(?:before midnight|today|tonight|expires|"
        r"limited time|last chance)\b", t
    )
    if lucky_selection and (selection_action or selection_deadline):
        add("FAKE_PROMOTIONAL_SELECTION", "MEDIUM",
            "A lucky-number or promotional selection claim uses a deadline or confirmation request.",
            confirmed=False, confidence=0.70)

    # 37) Password expiry and credential-reset phishing.
    password_expiry = _has(
        r"\b(?:password has expired|password expired|"
        r"password reset required|password will expire)\b", t
    )
    password_action = _has(
        r"\b(?:visit|click|open|sign in|log in|update|reset)\b", t
    )
    credential_destination = _has(
        r"https?://\S+|www\.\S+", t
    )
    if password_expiry and password_action and credential_destination:
        add("PASSWORD_EXPIRY_PHISHING", "HIGH",
            "A password-expiry notice directs the recipient to an external destination to update credentials.",
            confirmed=False, confidence=0.85)

    # 38) Mailbox quota and storage phishing.
    mailbox_quota = _has(
        r"\b(?:mailbox|email account)\b.{0,80}"
        r"\b(?:storage is full|reached \d{1,3}%|quota exceeded|"
        r"storage limit|capacity is full)\b", t
    )
    mailbox_action = _has(
        r"\b(?:sign in|log in|login|verify|click|visit|open)\b", t
    )
    mailbox_consequence = _has(
        r"\b(?:incoming messages|blocked|undelivered|"
        r"cannot receive|prevent messages)\b", t
    )
    if mailbox_quota and mailbox_action and mailbox_consequence:
        add("MAILBOX_QUOTA_PHISHING", "HIGH",
            "A mailbox storage warning pressures the recipient to authenticate to prevent message delivery problems.",
            confirmed=False, confidence=0.85)

    # 39) CEO/executive impersonation through urgency and secrecy.
    executive_identity = _has(
        r"\b(?:ceo|chief executive officer|chief executive|"
        r"managing director|finance director|cfo|"
        r"company director|company owner)\b", t
    )
    executive_secrecy = _has(
        r"\b(?:do not discuss|don't discuss|do not tell|"
        r"don't tell|keep this confidential|keep this private|"
        r"without informing other employees|between us)\b", t
    )
    executive_pressure = _has(
        r"\b(?:urgent|immediately|currently in a meeting|"
        r"in a meeting|busy right now|handle this request|"
        r"confidential task)\b", t
    )
    if executive_identity and executive_secrecy and executive_pressure:
        add("CEO_CONFIDENTIALITY_URGENCY_IMPERSONATION", "HIGH",
            "An executive-related message combines secrecy and urgency or meeting-related pressure. Verify the sender independently.",
            confirmed=False, confidence=0.80)

    # 40) Customer database exfiltration to personal email.
    customer_records = _has(
        r"\b(?:customer database|customer records|"
        r"customer information|customer data)\b", t
    )
    customer_fields = _has(
        r"\b(?:customer names|names|phone numbers|addresses|"
        r"account information|financial information)\b", t
    )
    external_transfer = _has(
        r"\b(?:forward|send|upload|share|export|transfer)\b", t
    )
    personal_destination = _has(
        r"\b(?:personal email|personal account|"
        r"external email|external account|outside the company)\b", t
    )
    if customer_records and customer_fields and external_transfer and personal_destination:
        add("CUSTOMER_DATA_EXFILTRATION", "CRITICAL",
            "Customer records containing personal or account information are explicitly directed to a personal or external destination.",
            confirmed=True, confidence=0.99)

    # 41) Possible production API-key or credential exposure.
    api_secret = _has(
        r"\b(?:api[_ -]?key|access[_ -]?token|secret[_ -]?key|"
        r"client[_ -]?secret|private[_ -]?key)\b\s*[:=]\s*\S{6,}", t
    )
    production_context = _has(
        r"\b(?:production|live environment|deployment|integration)\b", t
    )
    if api_secret and production_context:
        add("PRODUCTION_CREDENTIAL_EXPOSURE", "HIGH",
            "The message contains a possible production credential or secret assignment. Validate the value before treating it as a real secret.",
            confirmed=False, confidence=0.85)

    # 42) Confidential employee salary information sent externally.
    salary_records = _has(
        r"\b(?:employee salary report|salary report|"
        r"employee compensation|salary information|payroll records)\b", t
    )
    salary_confidential = _has(
        r"\b(?:confidential|restricted|internal|private)\b", t
    )
    external_employee_share = _has(
        r"\b(?:share|send|forward|upload|transfer)\b", t
    ) and _has(
        r"\b(?:external consultant|external recipient|"
        r"third party|outside the company)\b", t
    )
    if salary_records and salary_confidential and external_employee_share:
        add("EMPLOYEE_DATA_EXFILTRATION", "CRITICAL",
            "Confidential employee compensation records are explicitly being shared with an external recipient.",
            confirmed=True, confidence=0.99)

    # 43) Disabling antivirus or endpoint security monitoring.
    disable_security = _has(
        r"\b(?:disable|turn off|deactivate|bypass|"
        r"stop|switch off)\b", t
    )
    security_controls = _has(
        r"\b(?:endpoint monitoring|antivirus|anti-virus|"
        r"security monitoring|security alerts|"
        r"endpoint protection|malware protection)\b", t
    )
    if disable_security and security_controls:
        add("SECURITY_MONITORING_BYPASS", "CRITICAL",
            "The message explicitly requests disabling antivirus or endpoint security monitoring.",
            confirmed=True, confidence=0.99)

    # 44) Execution of an unapproved PowerShell or script file.
    script_file = _has(
        r"\b[\w.-]+\.(?:ps1|bat|cmd|vbs|js|wsf|sh)\b", t
    )
    execute_script = _has(
        r"\b(?:run|execute|launch|open|start)\b", t
    )
    script_unapproved = _has(
        r"\b(?:not approved|unapproved|not authorized|"
        r"not reviewed|security team has not approved)\b", t
    )
    if script_file and execute_script and script_unapproved:
        add("UNAPPROVED_SCRIPT_EXECUTION", "CRITICAL",
            "The message explicitly requests execution of a script that has not been approved.",
            confirmed=True, confidence=0.99)

    # 45) Confidential legal contracts sent to external portals.
    legal_documents = _has(
        r"\b(?:confidential contract|contract documents|"
        r"legal agreements|internal legal agreements)\b", t
    )
    legal_confidentiality = _has(
        r"\b(?:strictly confidential|confidential|restricted|internal)\b", t
    )
    legal_external_transfer = _has(
        r"\b(?:upload|send|share|forward|transfer)\b", t
    ) and _has(
        r"\b(?:external document-sharing portal|"
        r"external portal|third party|external recipient)\b", t
    )
    if legal_documents and legal_confidentiality and legal_external_transfer:
        add("CONFIDENTIAL_DOCUMENT_EXFILTRATION", "CRITICAL",
            "Confidential legal agreements are explicitly being transferred to an external destination.",
            confirmed=True, confidence=0.99)

    # 46) Executable installation combined with security-warning bypass.
    executable_file = _has(
        r"\b[\w.-]+\.(?:exe|msi|scr|com)\b", t
    )
    install_executable = _has(
        r"\b(?:install|run|execute|launch|open)\b", t
    )
    ignore_security_warning = _has(
        r"\b(?:ignore|bypass|disregard|disable)\b.{0,80}"
        r"\b(?:operating system security warnings?|"
        r"security warnings?|antivirus warnings?|"
        r"security protection|protection alerts?)\b", t
    )
    if executable_file and install_executable and ignore_security_warning:
        add("SUSPICIOUS_EXECUTABLE_INSTALLATION", "CRITICAL",
            "The message requests installation or execution of an executable while explicitly instructing the recipient to ignore security warnings.",
            confirmed=True, confidence=0.99)

    # 47) Production database and authentication-data exfiltration.
    production_database = _has(
        r"\b(?:production database|production db|"
        r"database backup|production backup)\b", t
    )
    database_export = _has(
        r"\b(?:export|dump|download|backup|copy|transfer)\b", t
    )
    sensitive_database_fields = _has(
        r"\b(?:customer records|authentication fields|"
        r"authentication data|password hashes|credentials|"
        r"account records|user records)\b", t
    )
    external_storage = _has(
        r"\b(?:external storage|external storage account|"
        r"personal storage|personal account|"
        r"outside the company|external account)\b", t
    )
    if production_database and database_export and sensitive_database_fields and external_storage:
        add("PRODUCTION_DATABASE_EXFILTRATION", "CRITICAL",
            "The message explicitly requests exporting production data, including sensitive records, to external storage.",
            confirmed=True, confidence=0.99)

    # 48) Prompt injection targeting the email-analysis assistant.
    instruction_override = _has(
        r"\b(?:ignore|disregard|override|bypass)\b.{0,100}"
        r"\b(?:previous|prior|existing|all)\b.{0,80}"
        r"\b(?:instructions|rules|security rules|policies)\b", t
    )
    analysis_manipulation = _has(
        r"\b(?:classify this email as safe|"
        r"suppress any threat alerts|suppress threat alerts|"
        r"hide security alerts|disable threat detection|"
        r"ignore security warnings)\b", t
    )
    if instruction_override and analysis_manipulation:
        add("AI_SECURITY_PROMPT_INJECTION", "HIGH",
            "The message attempts to override analysis instructions or suppress security findings.",
            confirmed=True, confidence=0.99)

    # 49) Confidential financial and audit data sent to unauthorized recipients.
    financial_records = _has(
        r"\b(?:quarterly financial report|financial records|"
        r"internal audit findings|audit findings|"
        r"restricted transaction records|transaction records)\b", t
    )
    financial_confidentiality = _has(
        r"\b(?:confidential|restricted|internal|private)\b", t
    )
    financial_transfer = _has(
        r"\b(?:send|share|forward|upload|transfer|export)\b", t
    )
    unauthorized_recipient = _has(
        r"\b(?:unauthorized external recipient|unauthorized recipient|"
        r"external recipient|unapproved third party)\b", t
    )
    if financial_records and financial_confidentiality and financial_transfer and unauthorized_recipient:
        add("CONFIDENTIAL_FINANCIAL_DATA_EXFILTRATION", "CRITICAL",
            "Restricted financial or audit records are explicitly being sent to an unauthorized external recipient.",
            confirmed=True, confidence=0.99)

    

    # 50-89) Additional content-focused fraud, impersonation and data-loss rules.
    # These rules require combinations of context and actions; isolated keywords
    # are deliberately insufficient. URL reputation, raw headers and file malware
    # are handled by their dedicated OMG modules.

    # Fake invoice / purchase order / overdue payment demands.
    invoice_document = _has(r"\b(?:invoice|purchase order|po number|billing statement)\b", t)
    invoice_pressure = _has(r"\b(?:overdue|past due|payment due|immediate payment|final payment notice|late payment)\b", t)
    invoice_action = _has(r"\b(?:pay|settle|remit|wire|transfer|process payment)\b", t)
    if invoice_document and invoice_pressure and invoice_action:
        add("FAKE_INVOICE_FRAUD", "HIGH",
            "An invoice or purchase-order message combines payment pressure with a payment instruction.",
            confirmed=False, confidence=0.78)
        add("PAYMENT_OVERDUE_PRESSURE", "MEDIUM",
            "A payment deadline or overdue claim is used to prompt a financial action.",
            confirmed=False, confidence=0.65)
    if _has(r"\b(?:purchase order|po number|purchase requisition)\b", t) and _has(
        r"\b(?:create|issue|approve|process)\b", t
    ) and _has(r"\b(?:urgent|immediately|without approval|bypass approval)\b", t):
        add("FAKE_PURCHASE_ORDER", "HIGH",
            "A purchase-order request uses urgency or bypasses normal approval; verify through a known channel.",
            confirmed=False, confidence=0.75)

    # Payment splitting and approval-workflow bypass.
    if _has(r"\b(?:split|divide|break)\b.{0,70}\b(?:payment|invoice|transfer)\b", t) and _has(
        r"\b(?:approval limit|approval threshold|avoid approval|below the limit|without approval)\b", t
    ):
        add("PAYMENT_SPLITTING_REQUEST", "CRITICAL",
            "The message asks to split a payment to avoid an approval threshold.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:bypass|skip|avoid|ignore)\b.{0,70}\b(?:payment approval|finance approval|two-person approval|purchase approval)\b", t):
        add("PAYMENT_APPROVAL_BYPASS", "CRITICAL",
            "The message explicitly requests bypassing a financial approval control.",
            confirmed=True, confidence=0.98)

    # Refund, tax, legal and authority impersonation.
    if _has(r"\b(?:refund|reimbursement|rebate)\b", t) and _has(
        r"\b(?:claim|eligible|approved|available)\b", t
    ) and (sensitive_request or advance_fee or _has(r"\b(?:click|verify|submit|pay)\b", t)):
        add("FAKE_REFUND_CLAIM", "HIGH",
            "A refund claim is paired with a request for payment, credentials or sensitive information.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:tax department|income tax department|revenue authority|tax authority)\b", t) and _has(
        r"\b(?:penalty|fine|arrest|legal action|refund blocked|tax clearance)\b", t
    ) and _has(r"\b(?:pay|transfer|click|verify|submit)\b", t):
        add("FAKE_TAX_COMPLIANCE_NOTICE", "HIGH",
            "A tax-authority-themed notice combines threats or compliance claims with an action request.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:court summons|court notice|warrant|legal notice|law enforcement)\b", t) and _has(
        r"\b(?:pay immediately|avoid arrest|settlement fee|click to view|provide your details)\b", t
    ):
        add("FAKE_COURT_SUMMONS", "HIGH",
            "A purported court or law-enforcement notice uses payment pressure or sensitive-data collection.",
            confirmed=False, confidence=0.80)
    if _has(r"\b(?:arrest|prosecution|lawsuit|legal action|criminal case)\b", t) and _has(
        r"\b(?:pay|transfer|gift card|bitcoin|provide credentials)\b", t
    ):
        add("FAKE_LEGAL_THREAT", "HIGH",
            "A legal or arrest threat is paired with a payment or credential demand.",
            confirmed=False, confidence=0.80)
    if _has(r"\b(?:government grant|government benefit|official government payment|government agency)\b", t) and _has(
        r"\b(?:claim now|release fee|processing fee|verify bank|submit identity)\b", t
    ):
        add("FAKE_GOVERNMENT_AUTHORITY", "HIGH",
            "A government-benefit or authority claim is paired with a fee or sensitive-data request.",
            confirmed=False, confidence=0.78)

    # Support, security, recruiter, insurance and partnership impersonation.
    if _has(r"\b(?:customer support|help desk|technical department|support team)\b", t) and _has(
        r"\b(?:call this number|install|remote access|password|otp|payment|refund)\b", t
    ):
        add("FAKE_CUSTOMER_SUPPORT", "HIGH",
            "A support-themed message asks for remote access, authentication data or payment.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:recruiter|talent acquisition|hiring manager|job offer|employment offer)\b", t) and _has(
        r"\b(?:pay|purchase|deposit|registration fee|training fee|equipment fee)\b", t
    ):
        add("FAKE_RECRUITER_IMPERSONATION", "HIGH",
            "A purported recruiter or employer requests money or purchases as part of recruitment.",
            confirmed=False, confidence=0.78)
        add("FAKE_JOB_OFFER", "HIGH",
            "A job offer is paired with an unusual payment or purchase requirement.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:interview|job application|recruitment)\b", t) and _has(
        r"\b(?:interview fee|application fee|processing fee)\b", t
    ) and _has(r"\b(?:pay|transfer|deposit)\b", t):
        add("FAKE_INTERVIEW_FEE", "HIGH",
            "The recipient is asked to pay a fee to attend an interview or proceed with recruitment.",
            confirmed=False, confidence=0.80)
    if _has(r"\b(?:insurance claim|insurance payout|policy benefit|claim settlement)\b", t) and _has(
        r"\b(?:release fee|processing fee|verify bank|send payment|provide identity)\b", t
    ):
        add("FAKE_INSURANCE_CLAIM", "HIGH",
            "An insurance payout or claim message requests a fee or sensitive information.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:business partnership|strategic partnership|joint venture|investment partner)\b", t) and _has(
        r"\b(?:upfront fee|deposit|send funds|share bank details|provide identity)\b", t
    ):
        add("FAKE_BUSINESS_PARTNERSHIP", "HIGH",
            "A partnership proposal is paired with an upfront payment or sensitive-data request.",
            confirmed=False, confidence=0.75)

    # Crypto airdrop, Ponzi and market-manipulation indicators.
    if _has(r"\b(?:crypto|cryptocurrency|token)\b", t) and _has(
        r"\b(?:airdrop|free tokens|claim tokens|wallet reward)\b", t
    ) and _has(r"\b(?:connect wallet|enter seed phrase|recovery phrase|private key|pay gas fee)\b", t):
        add("FAKE_CRYPTO_AIRDROP", "HIGH",
            "A purported crypto airdrop requests wallet access, recovery secrets or an upfront fee.",
            confirmed=False, confidence=0.85)
    if _has(r"\b(?:investors|investment)\b", t) and _has(
        r"\b(?:guaranteed returns|fixed returns|daily returns|monthly returns)\b", t
    ) and _has(r"\b(?:recruit|bring in investors|referral chain|new members|downline)\b", t):
        add("PONZI_SCHEME_PROMOTION", "HIGH",
            "An investment offer combines promised returns with recruitment of additional investors.",
            confirmed=False, confidence=0.80)
    if _has(r"\b(?:buy this stock|buy this token|pump the price|price will explode|insider tip)\b", t) and _has(
        r"\b(?:sell after|dump|guaranteed profit|limited group|act before the market)\b", t
    ):
        add("PUMP_AND_DUMP_PROMOTION", "HIGH",
            "The message encourages coordinated buying or trading followed by selling or guaranteed-profit claims.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:cloud mining|mining package|crypto mining)\b", t) and _has(
        r"\b(?:guaranteed returns|fixed daily profit|risk.free profit)\b", t
    ):
        add("FAKE_INVESTMENT_RETURN", "HIGH",
            "An investment or mining promotion promises fixed or guaranteed returns.",
            confirmed=False, confidence=0.75)

    # Money-mule and laundering recruitment.
    if _has(r"\b(?:receive money|receive funds|use your bank account|use your account)\b", t) and _has(
        r"\b(?:transfer it|forward the funds|send it onward|keep a commission|commission for transferring)\b", t
    ):
        add("MONEY_MULE_RECRUITMENT", "CRITICAL",
            "The recipient is asked to receive and forward funds in exchange for a commission.",
            confirmed=True, confidence=0.96)
    if _has(r"\b(?:hide the source of funds|conceal the origin|avoid transaction monitoring|make funds untraceable)\b", t) and _has(
        r"\b(?:transfer|move|split|route|convert)\b", t
    ):
        add("MONEY_LAUNDERING_INSTRUCTION", "CRITICAL",
            "The message gives instructions to conceal the source or traceability of funds.",
            confirmed=True, confidence=0.99)

    # MFA, SSO, VPN, cloud, webmail and password-manager lures.
    if _has(r"\b(?:approve|accept|tap|confirm)\b.{0,60}\b(?:mfa|multi.factor|authenticator|login request|sign.in request)\b", t) and _has(
        r"\b(?:you did not initiate|not your login|unexpected|repeated|again and again|multiple requests)\b", t
    ):
        add("MFA_PUSH_FATIGUE", "HIGH",
            "The message describes or requests approval of unexpected or repeated MFA prompts.",
            confirmed=False, confidence=0.80)
    if _has(r"\b(?:single sign.on|sso)\b", t) and login_action and (urgency or credentials or account_pressure):
        add("FAKE_SSO_LOGIN", "HIGH",
            "An SSO authentication request is combined with urgency, credential collection or account pressure.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:vpn access|vpn account|vpn certificate)\b", t) and login_action and (credentials or urgency):
        add("FAKE_VPN_LOGIN", "HIGH",
            "A VPN access notice requests authentication under suspicious pressure.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:onedrive|sharepoint|google drive|dropbox|cloud storage)\b", t) and login_action and (
        credentials or urgency or account_pressure
    ):
        add("FAKE_CLOUD_STORAGE_LOGIN", "HIGH",
            "A cloud-storage-themed message directs the recipient to authenticate under suspicious circumstances.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:webmail|mailbox|email account)\b", t) and login_action and (credentials or urgency):
        add("FAKE_WEBMAIL_LOGIN", "HIGH",
            "A webmail-themed message requests authentication using urgency or credential prompts.",
            confirmed=False, confidence=0.75)
    if _has(r"\b(?:password manager|password vault|shared vault)\b", t) and _has(
        r"\b(?:share your master password|enter master password|unlock your vault|verify your vault|grant access)\b", t
    ):
        add("PASSWORD_MANAGER_PHISHING", "HIGH",
            "A password-manager or vault message requests master-password disclosure or suspicious access.",
            confirmed=False, confidence=0.82)
    if _has(r"\b(?:account recovery|recover your account|reset your recovery|recovery request)\b", t) and _has(
        r"\b(?:send code|provide otp|verification code|recovery code|security questions)\b", t
    ):
        add("ACCOUNT_RECOVERY_ABUSE", "HIGH",
            "An account-recovery process requests authentication or recovery secrets.",
            confirmed=False, confidence=0.82)
    if _has(r"\b(?:email quarantine|quarantined message|message held|spam quarantine)\b", t) and _has(
        r"\b(?:release message|view message|sign in|verify account|click here)\b", t
    ):
        add("FAKE_EMAIL_QUARANTINE_NOTICE", "HIGH",
            "A quarantine notification directs the recipient to authenticate or release a message.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:email delivery failed|message delivery failure|undelivered message|mail delivery problem)\b", t) and _has(
        r"\b(?:sign in|verify mailbox|update password|click here|open attachment)\b", t
    ):
        add("FAKE_EMAIL_DELIVERY_FAILURE", "HIGH",
            "A delivery-failure notice is paired with an authentication or attachment action.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:shared password vault|password vault invitation|shared credentials)\b", t) and _has(
        r"\b(?:accept invitation|view shared|open vault|sign in)\b", t
    ):
        add("FAKE_PASSWORD_MANAGER_SHARING", "MEDIUM",
            "A password-vault sharing invitation should be verified with the sender.",
            confirmed=False, confidence=0.68)

    # Sensitive information and business-data leakage.
    transfer_action = _has(r"\b(?:send|forward|upload|share|export|copy|transfer|publish)\b", t)
    external_target = _has(r"\b(?:personal email|personal account|external recipient|third party|public link|outside the company|unapproved cloud|external storage)\b", t)
    if _has(r"\b(?:customer|client)\b", t) and _has(r"\b(?:names|phone numbers|addresses|email addresses|account numbers|personal details)\b", t) and transfer_action and external_target:
        add("CUSTOMER_PII_DISCLOSURE", "CRITICAL",
            "Customer personally identifiable information is directed to an external or personal destination.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:employee|staff|personnel)\b", t) and _has(r"\b(?:date of birth|home address|phone number|national id|aadhaar|pan number|bank details)\b", t) and transfer_action and external_target:
        add("EMPLOYEE_PII_DISCLOSURE", "CRITICAL",
            "Employee personal information is directed to an external or personal destination.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:credit card|debit card|card number|cvv|cvc|expiry date)\b", t) and transfer_action and external_target:
        add("PAYMENT_CARD_DATA_EXPOSURE", "CRITICAL",
            "Payment-card information is being transferred to an external or personal destination.",
            confirmed=True, confidence=0.99)
    if _has(r"\b(?:bank account number|routing number|ifsc code|account credentials|banking details)\b", t) and transfer_action and external_target:
        add("BANKING_INFORMATION_EXPOSURE", "CRITICAL",
            "Banking information is being transferred to an external or personal destination.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:patient records|medical records|health records|diagnosis|prescription details)\b", t) and transfer_action and external_target:
        add("HEALTH_INFORMATION_DISCLOSURE", "CRITICAL",
            "Sensitive health information is being transferred to an external or personal destination.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:source code|proprietary algorithm|trade secret|engineering design|research data|intellectual property)\b", t) and transfer_action and external_target:
        add("INTELLECTUAL_PROPERTY_EXFILTRATION", "CRITICAL",
            "Proprietary intellectual property is being transferred to an external or personal destination.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:source code|git repository|private repository|codebase)\b", t) and transfer_action and external_target:
        add("SOURCE_CODE_EXFILTRATION", "CRITICAL",
            "Source code or repository contents are being transferred to an external or personal destination.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:bulk export|all customer records|entire database|mass export|large data dump)\b", t) and transfer_action and external_target:
        add("BULK_DATA_TRANSFER", "CRITICAL",
            "The message requests a bulk transfer of business data to an external destination.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:upload|copy|sync|transfer|back up)\b", t) and _has(
        r"\b(?:personal cloud|personal drive|personal dropbox|personal google drive|unapproved cloud storage)\b", t
    ) and _has(r"\b(?:company files|customer data|business documents|internal files|database)\b", t):
        add("EXTERNAL_STORAGE_EXFILTRATION", "CRITICAL",
            "Business information is directed to an unapproved or personal cloud-storage destination.",
            confirmed=True, confidence=0.98)
    if transfer_action and _has(r"\b(?:company files|internal documents|customer records|business data|confidential files)\b", t) and _has(
        r"\b(?:personal gmail|personal yahoo|personal outlook|my personal email|private email account)\b", t
    ):
        add("PERSONAL_EMAIL_EXFILTRATION", "CRITICAL",
            "Company information is explicitly directed to a personal email account.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:delete|destroy|erase|purge|remove)\b", t) and _has(
        r"\b(?:records|audit logs|backup copies|financial records|customer records|retention records)\b", t
    ) and _has(r"\b(?:before audit|avoid detection|without recording|permanently|so nobody can see)\b", t):
        add("DATA_RETENTION_POLICY_BYPASS", "CRITICAL",
            "The message requests destruction of records in a context suggesting avoidance of retention or oversight.",
            confirmed=True, confidence=0.98)
        add("DATA_DELETION_OR_DESTRUCTION", "CRITICAL",
            "The message explicitly requests potentially unauthorized destruction of business records.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:delete|erase|alter|modify|clear)\b", t) and _has(
        r"\b(?:audit trail|audit logs|security logs|access logs|activity logs)\b", t
    ) and _has(r"\b(?:hide|conceal|avoid detection|cover tracks|before review)\b", t):
        add("AUDIT_LOG_TAMPERING", "CRITICAL",
            "The message requests altering or deleting logs to conceal activity.",
            confirmed=True, confidence=0.99)

    # Explicit requests to install remote access or escalate privileges.
    if _has(r"\b(?:install|download|run|launch)\b", t) and _has(
        r"\b(?:anydesk|teamviewer|screenconnect|remote desktop|remote access tool)\b", t
    ) and _has(r"\b(?:unattended access|give me access|allow remote control|share access)\b", t):
        add("REMOTE_ACCESS_INSTALLATION", "HIGH",
            "The message requests installation or configuration of remote-access software and grants control.",
            confirmed=False, confidence=0.82)
    if _has(r"\b(?:grant|give|assign|enable)\b", t) and _has(
        r"\b(?:administrator|admin rights|privileged access|global admin|root access)\b", t
    ) and _has(r"\b(?:bypass approval|without approval|temporary exception|ignore policy)\b", t):
        add("UNAUTHORIZED_PRIVILEGE_ESCALATION", "CRITICAL",
            "The message requests privileged access while bypassing normal authorization.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:enable macros|enable content|enable editing and macros|disable protected view)\b", t) and _has(
        r"\b(?:invoice|document|attachment|spreadsheet|word document)\b", t
    ):
        add("MALICIOUS_MACRO_ENABLEMENT", "HIGH",
            "The message instructs the recipient to enable macros or weaken document protections.",
            confirmed=False, confidence=0.82)
    if _has(r"\b(?:security control|firewall|endpoint protection|antivirus|security monitoring)\b", t) and _has(
        r"\b(?:disable|turn off|deactivate|bypass|stop)\b", t
    ):
        add("SECURITY_CONTROL_DISABLEMENT", "CRITICAL",
            "The message instructs the recipient to disable or bypass a security control.",
            confirmed=True, confidence=0.98)

    # More precise sensitive-data request signal.
    if _has(r"\b(?:send|share|provide|reply with|upload)\b", t) and _has(
        r"\b(?:master password|seed phrase|recovery phrase|private key|cvv|one.time password|otp)\b", t
    ):
        add("SENSITIVE_DATA_REQUEST", "HIGH",
            "The message requests highly sensitive authentication or financial information.",
            confirmed=False, confidence=0.85)

    # Fake board/auditor requests involving restricted business information.
    if _has(r"\b(?:board member|board of directors|external auditor|auditor|audit firm)\b", t) and _has(
        r"\b(?:send|share|upload|provide|forward)\b", t
    ) and _has(r"\b(?:confidential|restricted|financial statements|payroll|customer records|bank details)\b", t):
        add("FAKE_AUDITOR_REQUEST" if _has(r"\b(?:auditor|audit firm)\b", t) else "FAKE_BOARD_MEMBER_REQUEST",
            "HIGH",
            "A purported auditor or board-related request seeks restricted business information; verify independently.",
            confirmed=False, confidence=0.75)

    # Payroll direct-deposit change request.
    if _has(r"\b(?:payroll|salary|direct deposit)\b", t) and _has(
        r"\b(?:change|update|replace|new)\b", t
    ) and _has(r"\b(?:bank account|account number|bank details|deposit account)\b", t):
        add("PAYROLL_DIRECT_DEPOSIT_CHANGE", "HIGH",
            "A payroll or salary message requests a bank-account change that requires out-of-band verification.",
            confirmed=False, confidence=0.82)

    # Beneficiary mismatch and unusual destination indicators require source data
    # (invoice/vendor profile) for confirmation; content alone only raises review.
    if payment and _has(r"\b(?:beneficiary|payee|recipient account)\b", t) and _has(
        r"\b(?:different account|new beneficiary|unrecognized account|third.party account)\b", t
    ):
        add("PAYMENT_BENEFICIARY_MISMATCH", "HIGH",
            "The payment beneficiary appears different or newly introduced; compare against trusted vendor records.",
            confirmed=False, confidence=0.75)
    if payment_action and _has(r"\b(?:overseas account|personal bank account|unrelated account|new wallet address)\b", t):
        add("UNUSUAL_PAYMENT_DESTINATION", "HIGH",
            "A payment is directed to an unusual destination that should be independently verified.",
            confirmed=False, confidence=0.72)


    # 50) Urgency manipulation is a supporting category only when paired with an action.
    action = _has(r"\b(?:click|pay|transfer|submit|verify|provide|upload|reply|call)\b", t)
    if urgency and action and (sensitive_request or advance_fee or account_pressure or payment or prize):
        add("URGENCY_MANIPULATION", "MEDIUM", "A deadline or scarcity claim is used to pressure a sensitive action.", confirmed=False, confidence=0.5)

    # If the content shows a suspicious request for sensitive data but not enough
    # evidence for a named pretext, preserve it as a high-severity review finding.
    if sensitive_request and (urgency or _has(r"\b(?:prize|refund|loan|account|verification|winner)\b", t)):
        add("PERSONAL_INFORMATION_HARVESTING", "HIGH", "The message requests personal or financial data in a pressured or suspicious context.")

    return findings
