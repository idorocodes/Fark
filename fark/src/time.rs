
use std::time::{SystemTime, UNIX_EPOCH};
use crate::error::{TimeError};

pub(crate) fn now() -> Result<u64, TimeError>  {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TimeError::TimeGenError)?;
    Ok(time.as_secs())
}  