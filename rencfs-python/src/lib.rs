use pyo3::prelude::*;

pub mod fs;
pub mod types;

/// Returns the current version of the rencfs python bindings.
#[pyfunction]
fn version() -> PyResult<String> {
    Ok(env!("CARGO_PKG_VERSION").to_string())
}

/// The entrypoint for the `rencfs` Python module.
#[pymodule]
fn rencfs(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;

    m.add_class::<types::FileType>()?;
    m.add_class::<types::Cipher>()?;
    m.add_class::<types::CreateFileAttr>()?;
    m.add_class::<types::FileAttr>()?;
    m.add_class::<types::SetFileAttr>()?;
    m.add_class::<types::DirEntry>()?;
    m.add_class::<types::DirEntryPlus>()?;
    m.add_class::<fs::EncryptedFs>()?;

    Ok(())
}
