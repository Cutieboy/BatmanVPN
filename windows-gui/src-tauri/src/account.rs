use mousevpn_account_client::{Account, AccountClient, EnrollRequest};
use mousevpn_config::{encode_public_key, encode_secret_key};
use mousevpn_crypto::KeyPair;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, MutexGuard,
    },
};
use zeroize::{Zeroize, Zeroizing};

static ACCOUNT_LOCK: Mutex<()> = Mutex::new(());
static ACCOUNT_REVISION: AtomicU64 = AtomicU64::new(0);
/// Service addresses of earlier releases. Their sessions belong to the same center,
/// so a saved account moves to the current address with its token and device key.
const LEGACY_SERVICES: [&str; 2] = ["https://mousevpn.space/vpn", "https://myaifriend.su/vpn"];

fn primary() -> &'static str {
    option_env!("MOUSEVPN_ACCOUNT_URL").unwrap_or("https://ss.libekra.ru/api")
}

fn fallback() -> &'static str {
    option_env!("MOUSEVPN_ACCOUNT_FALLBACK_URL").unwrap_or("")
}

fn current_service(base: String) -> String {
    if LEGACY_SERVICES.contains(&base.as_str()) && base != fallback() {
        primary().to_owned()
    } else {
        base
    }
}

#[derive(Deserialize, Serialize)]
struct SavedAccount {
    base: String,
    token: String,
    private_key: String,
    public_key: String,
    account: Account,
}

impl Drop for SavedAccount {
    fn drop(&mut self) {
        self.token.zeroize();
        self.private_key.zeroize();
    }
}

#[derive(Serialize)]
pub(crate) struct AccountView {
    pub base: String,
    pub signed_in: bool,
    pub public_key: String,
    pub account: Option<Account>,
}

fn lock() -> Result<MutexGuard<'static, ()>, String> {
    ACCOUNT_LOCK
        .lock()
        .map_err(|_| "Аккаунт недоступен".to_owned())
}

pub(crate) fn view() -> Result<AccountView, String> {
    let _guard = lock()?;
    let saved = read()?;
    Ok(saved.as_ref().map_or_else(
        || AccountView {
            base: primary().to_owned(),
            signed_in: false,
            public_key: String::new(),
            account: None,
        },
        |saved| AccountView {
            base: saved.base.clone(),
            signed_in: !saved.token.is_empty(),
            public_key: saved.public_key.clone(),
            account: Some(saved.account.clone()),
        },
    ))
}

pub(crate) fn login(base: String, login: String, password: String) -> Result<AccountView, String> {
    let _guard = lock()?;
    let password = Zeroizing::new(password);
    let (primary, fallback) = (primary(), fallback());
    let mut base = if base.trim().is_empty() {
        primary.to_owned()
    } else {
        current_service(base.trim().trim_end_matches('/').to_owned())
    };
    let mut response = AccountClient::new(&base)?.login(&login, &password);
    if base == primary
        && !fallback.is_empty()
        && response
            .as_ref()
            .is_err_and(|error| error == "Сервис аккаунтов недоступен")
    {
        fallback.clone_into(&mut base);
        response = AccountClient::new(&base)?.login(&login, &password);
    }
    let response = response?;
    let client = AccountClient::new(&base)?;
    let previous = read()?;
    let (private_key, public_key) = if let Some(previous) = previous.filter(|saved| {
        saved.account.id == response.account.id
            && (saved.base == base
                || ([primary, fallback].contains(&saved.base.as_str())
                    && [primary, fallback].contains(&base.as_str())))
    }) {
        (previous.private_key.clone(), previous.public_key.clone())
    } else {
        let keys = KeyPair::generate().map_err(|error| error.to_string())?;
        (
            encode_secret_key(&keys.secret),
            encode_public_key(&keys.public),
        )
    };
    let mut saved = SavedAccount {
        base,
        token: response.token,
        private_key,
        public_key,
        account: response.account,
    };
    write(&saved)?;
    saved.account = client.enroll(
        &saved.token,
        &EnrollRequest {
            name: "Windows".to_owned(),
            platform: "windows".to_owned(),
            public_key: saved.public_key.clone(),
        },
    )?;
    apply(&saved)?;
    Ok(as_view(&saved))
}

pub(crate) fn refresh() -> Result<AccountView, String> {
    let (request, revision) = {
        let _guard = lock()?;
        (read()?, ACCOUNT_REVISION.load(Ordering::Relaxed))
    };
    let Some(request) = request else {
        return view();
    };
    if request.token.is_empty() {
        return Ok(as_view(&request));
    }
    let account = AccountClient::new(&request.base)?.account(&request.token)?;
    let _guard = lock()?;
    let Some(mut saved) = read()? else {
        return Err("Войдите в аккаунт".into());
    };
    if ACCOUNT_REVISION.load(Ordering::Relaxed) == revision
        && saved.token == request.token
        && saved.base == request.base
        && saved.public_key == request.public_key
        && saved.account.id == request.account.id
    {
        saved.account = account;
        apply(&saved)?;
    }
    Ok(as_view(&saved))
}

pub(crate) fn revoke(id: &str) -> Result<AccountView, String> {
    let _guard = lock()?;
    super::profiles::normalized_id(id)?;
    let mut saved = read()?.ok_or("Войдите в аккаунт")?;
    saved.account = AccountClient::new(&saved.base)?.revoke(&saved.token, id)?;
    apply(&saved)?;
    Ok(as_view(&saved))
}

pub(crate) fn logout() -> Result<AccountView, String> {
    let _guard = lock()?;
    if let Some(mut saved) = read()? {
        let _ = AccountClient::new(&saved.base)?.logout(&saved.token);
        saved.token.clear();
        write(&saved)?;
        super::profiles::replace_managed(None)?;
        return Ok(as_view(&saved));
    }
    Ok(AccountView {
        base: String::new(),
        signed_in: false,
        public_key: String::new(),
        account: None,
    })
}

pub(crate) fn private_key(user: &str, server: &str) -> Result<String, String> {
    // Reconciliation already holds ACCOUNT_LOCK.
    let saved = read()?.ok_or("Войдите в аккаунт")?;
    cached_server(&saved, user, server)?;
    Ok(saved.private_key.clone())
}
fn cached_server<'a>(
    saved: &'a SavedAccount,
    user: &str,
    server: &str,
) -> Result<&'a mousevpn_account_client::Server, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(i64::MAX, |time| {
            i64::try_from(time.as_secs()).unwrap_or(i64::MAX)
        });
    if saved.token.is_empty()
        || saved.account.id != user
        || !saved.account.active
        || saved.account.valid_until <= now
        || !saved
            .account
            .devices
            .iter()
            .any(|device| device.public_key == saved.public_key)
        || !saved.account.servers.iter().any(|node| node.id == server)
    {
        return Err("Подписка истекла или доступ отключён. Обновите аккаунт.".to_owned());
    }
    saved
        .account
        .servers
        .iter()
        .find(|node| node.id == server)
        .ok_or_else(|| "Сервер недоступен".into())
}
pub(crate) fn with_server<T>(
    user: &str,
    server: &str,
    operation: impl FnOnce(&mousevpn_account_client::Server) -> Result<T, String>,
) -> Result<T, String> {
    let _guard = lock()?;
    let saved = read()?.ok_or("Войдите в аккаунт")?;
    operation(cached_server(&saved, user, server)?)
}

fn support_call<T>(
    call: impl FnOnce(&AccountClient, &str) -> Result<T, String>,
) -> Result<T, String> {
    let saved = {
        let _guard = lock()?;
        read()?.ok_or("Войдите в аккаунт")?
    };
    if saved.token.is_empty() {
        return Err("Войдите в аккаунт".to_owned());
    }
    call(&AccountClient::new(&saved.base)?, &saved.token)
}
pub(crate) fn tickets() -> Result<Vec<mousevpn_account_client::TicketSummary>, String> {
    support_call(AccountClient::tickets)
}
pub(crate) fn create_ticket(
    subject: &str,
    text: &str,
) -> Result<mousevpn_account_client::TicketDetail, String> {
    support_call(|client, token| client.create_ticket(token, subject, text))
}
pub(crate) fn ticket(
    id: &str,
    before: Option<i64>,
) -> Result<mousevpn_account_client::TicketDetail, String> {
    support_call(|client, token| client.ticket(token, id, before))
}
pub(crate) fn reply(id: &str, text: &str) -> Result<mousevpn_account_client::TicketDetail, String> {
    support_call(|client, token| client.reply(token, id, text))
}

fn apply(saved: &SavedAccount) -> Result<(), String> {
    write(saved)?;
    let registered = saved.account.active
        && saved
            .account
            .devices
            .iter()
            .any(|device| device.public_key == saved.public_key);
    super::profiles::replace_managed(registered.then_some(&saved.account))
}
fn as_view(saved: &SavedAccount) -> AccountView {
    AccountView {
        base: saved.base.clone(),
        signed_in: !saved.token.is_empty(),
        public_key: saved.public_key.clone(),
        account: Some(saved.account.clone()),
    }
}
fn path() -> Result<PathBuf, String> {
    dirs::config_dir()
        .map(|dir| dir.join("MouseVPN").join("account.sealed"))
        .ok_or("Не найден каталог пользователя".to_owned())
}
fn read() -> Result<Option<SavedAccount>, String> {
    let path = path()?;
    let encrypted = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let mut plain = mousevpn_windows_client::unprotect_account(&encrypted)?;
    let result: Result<SavedAccount, _> =
        serde_json::from_slice(&plain).map_err(|_| "Хранилище аккаунта повреждено".to_owned());
    plain.zeroize();
    let mut saved = result?;
    saved.base = current_service(std::mem::take(&mut saved.base));
    Ok(Some(saved))
}
fn write(saved: &SavedAccount) -> Result<(), String> {
    let mut plain = serde_json::to_vec(saved).map_err(|error| error.to_string())?;
    let encrypted = mousevpn_windows_client::protect_account(&plain);
    plain.zeroize();
    let encrypted = encrypted?;
    let path = path()?;
    fs::create_dir_all(path.parent().ok_or("Неверный каталог")?)
        .map_err(|error| error.to_string())?;
    super::profiles::write_atomic(&path, &encrypted)?;
    ACCOUNT_REVISION.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

pub(crate) fn billing() -> Result<mousevpn_account_client::BillingView, String> {
    support_call(AccountClient::billing)
}
pub(crate) fn request_payment(
    request: mousevpn_account_client::NewPaymentRequest,
) -> Result<mousevpn_account_client::PaymentRequest, String> {
    support_call(|client, token| client.request_payment(token, &request))
}
