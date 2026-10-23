/// How many queued mails one run claims per company. The queue's hold (60 s) outlasts a run, so every mail a run
/// claims is sent or released before another run could take it.
pub const MAIL_CLAIM_BATCH: u32 = 20;

/// How many claims a queued mail is given before the worker drops it: the `mail_outbox` queue's `ATTEMPTS`, which
/// hands out no record claimed that often, so the last failed try deletes it rather than leaving it sealed forever.
pub const MAIL_ATTEMPTS: u32 = 6;

/// How long a mail the relay did not take waits before its second try, in seconds; each later try waits twice as
/// long as the one before, so the last of `MAIL_ATTEMPTS` tries comes about fifteen minutes after the first.
pub const MAIL_RETRY_FIRST_SECS: u64 = 30;

/// The most one exchange with the relay may take, in seconds (RFC 5321 §4.5.3.2 allows a server minutes per
/// command; a submission relay answers in seconds, and a run must end inside the queue's hold).
pub const MAIL_SEND_TIMEOUT_SECS: u64 = 20;

/// How often the mail worker runs, in seconds.
pub const MAIL_DELIVERY_INTERVAL_SECS: u64 = 5;

/// The most one run of the mail worker may take, in seconds: below the queue's 60-second hold.
pub const MAIL_DELIVERY_RUN_TIMEOUT_SECS: u64 = 45;

/// How long the link that confirms a new sign-in address works, in seconds.
pub const EMAIL_CHANGE_CONFIRM_SECS: u64 = 86_400;

/// How long a change of sign-in address is held after it was asked for, in seconds, so that the link mailed to the
/// old address can still cancel it (the change waits for this even when the new address was confirmed at once).
pub const EMAIL_CHANGE_HOLD_SECS: u64 = 86_400;

/// How often the address-change worker looks for changes whose hold is over, in seconds.
pub const EMAIL_CHANGE_APPLY_INTERVAL_SECS: u64 = 60;

/// The most one run of the address-change worker may take, in seconds: below its interval.
pub const EMAIL_CHANGE_APPLY_RUN_TIMEOUT_SECS: u64 = 45;

/// How many due address changes one run applies per company; the rest wait for the next run.
pub const EMAIL_CHANGE_APPLY_BATCH: u32 = 20;
