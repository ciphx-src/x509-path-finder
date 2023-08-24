use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

pub async fn load_material(certificate: &str) -> Vec<u8> {
    let path = Path::new(file!()).parent().unwrap().join(certificate);
    let mut file = File::open(path).await.unwrap();
    let mut data = vec![];
    file.read_to_end(&mut data).await.unwrap();
    data
}
