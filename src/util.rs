//! A utility module for common operations.

use std::{fs::File, path::Path};

use crate::{env::Env, error::Result};

/// Create and open a file.
pub fn create_new_file(env: &impl Env, path: impl AsRef<Path>) -> Result<File> {
    let path = path.as_ref();
    let abs_path = env.in_cwd(&path);
    File::create_new(abs_path)
        .map_err(|err| format!("cannot create '{}': {err}", path.display()).into())
}

/// Rename a file.
pub fn rename_path(env: &impl Env, old: impl AsRef<Path>, new: impl AsRef<Path>) -> Result<()> {
    let (old, new) = (old.as_ref(), new.as_ref());
    let abs_old = env.in_cwd(&old);
    let abs_new = env.in_cwd(&new);
    std::fs::rename(abs_old, abs_new).map_err(|err| {
        format!(
            "could not move '{}' to '{}': {err}",
            old.display(),
            new.display()
        )
        .into()
    })
}

/// Create a symlink.
#[cfg(unix)]
pub fn symlink(env: &impl Env, target: impl AsRef<Path>, link: impl AsRef<Path>) -> Result<()> {
    let (target, link) = (target.as_ref(), link.as_ref());
    let target_path = env.in_cwd(&target);
    let link_path = env.in_cwd(&link);
    std::os::unix::fs::symlink(target_path, link_path).map_err(|err| {
        format!(
            "could not create symlink '{}' to '{}': {err}",
            link.display(),
            target.display(),
        )
        .into()
    })
}

/// Create a symlink, overwriting if it already exists.
#[cfg(unix)]
pub fn symlink_force(
    env: &impl Env,
    target: impl AsRef<Path>,
    link: impl AsRef<Path>,
) -> Result<()> {
    use crate::error::in_context;

    let (target, link) = (target.as_ref(), link.as_ref());
    let mut temp = link.to_path_buf();
    temp.as_mut_os_string().push(".new");

    in_context(
        || {
            format!(
                "creating symlink '{}' to '{}'",
                link.display(),
                target.display()
            )
        },
        || {
            symlink(env, target, &temp)?;
            rename_path(env, &temp, link)?;
            Ok(())
        },
    )
}
