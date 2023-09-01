use crate::api::Certificate;
use std::fs::canonicalize;
use std::io;
use std::io::ErrorKind;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use url::Url;
use x509_cert::Certificate as NativeCertificate;
use x509_client::provided::default::DefaultX509Iterator;
use x509_client::X509ClientConfiguration;

pub async fn load_material(file: &str) -> io::Result<Vec<u8>> {
    let path = Path::new(file!())
        .parent()
        .ok_or_else(|| io::Error::new(ErrorKind::Other, "invalid path"))?
        .join(file);
    let mut file = File::open(path).await?;
    let mut data = vec![];
    file.read_to_end(&mut data).await?;
    Ok(data)
}

pub async fn load_native_certificates(file: &str) -> io::Result<Vec<NativeCertificate>> {
    let path = Path::new(file!())
        .parent()
        .ok_or_else(|| io::Error::new(ErrorKind::Other, "invalid path"))?
        .join(file);
    let path = canonicalize(path)?;
    let url =
        Url::from_file_path(&path).map_err(|_| io::Error::new(ErrorKind::Other, "invalid path"))?;
    let client = x509_client::X509Client::<DefaultX509Iterator>::new(X509ClientConfiguration {
        strict: false,
        files: true,
        limit: None,
        http_client: None,
    });
    Ok(client
        .get_all(&url)
        .await
        .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?
        .into_iter()
        .collect())
}

pub async fn load_certificates(file: &str) -> io::Result<Vec<Certificate>> {
    Ok(load_native_certificates(file)
        .await?
        .into_iter()
        .map(|c| c.into())
        .collect())
}
