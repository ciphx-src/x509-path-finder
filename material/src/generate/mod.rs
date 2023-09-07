use crate::generate::result::{CertificatePathGeneratorError, CertificatePathGeneratorResult};
use der::asn1::Ia5String;
use der::oid::db::rfc5280::ID_AD_CA_ISSUERS;
use der::{Decode, Encode};
use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder, X509Ref, X509};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{AccessDescription, AuthorityInfoAccessSyntax};
use x509_cert::Certificate;

pub mod result;

pub struct CertificatePathGenerator {}

impl CertificatePathGenerator {
    pub fn generate(
        depth: usize,
        authority_id: &str,
    ) -> CertificatePathGeneratorResult<Vec<x509_cert::Certificate>> {
        if depth < 1 {
            return Err(CertificatePathGeneratorError::Error(
                "depth less than 1".to_string(),
            ));
        }
        let mut path = vec![];
        let (mut last, mut last_key) = Self::build_root(authority_id)?;
        path.push(Certificate::from_der(last.to_der()?.as_slice())?);

        for name in 1..depth {
            (last, last_key) = if name == depth - 1 {
                Self::build_ee(
                    name.to_string().as_str(),
                    authority_id,
                    last.as_ref(),
                    last_key.as_ref(),
                )?
            } else {
                Self::build_ic(
                    name.to_string().as_str(),
                    authority_id,
                    last.as_ref(),
                    last_key.as_ref(),
                )?
            };

            path.push(Certificate::from_der(last.to_der()?.as_slice())?);
        }

        path.reverse();

        Ok(path)
    }

    fn build_root(name_str: &str) -> CertificatePathGeneratorResult<(X509, PKey<Private>)> {
        let mut builder = X509Builder::new()?;

        builder.set_version(2)?;

        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;

        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;

        builder.set_serial_number(Asn1Integer::from_bn(serial.as_ref())?.as_ref())?;

        builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        builder.append_extension(KeyUsage::new().critical().key_cert_sign().build()?)?;
        builder.append_extension(
            SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?,
        )?;

        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", name_str)?;
        let name = name.build();
        builder.set_issuer_name(name.as_ref())?;

        builder.set_subject_name(name.as_ref())?;

        let key = Self::gen_keypair()?;
        builder.set_pubkey(key.as_ref())?;

        builder.sign(key.as_ref(), MessageDigest::sha256())?;

        Ok((builder.build(), key))
    }

    fn build_ic(
        name_str: &str,
        authority_id: &str,
        issuer: &X509Ref,
        issuer_key: &PKeyRef<Private>,
    ) -> CertificatePathGeneratorResult<(X509, PKey<Private>)> {
        let mut builder = X509Builder::new()?;

        builder.set_version(2)?;

        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;

        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;

        builder.set_serial_number(Asn1Integer::from_bn(serial.as_ref())?.as_ref())?;

        builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        builder.append_extension(KeyUsage::new().critical().key_cert_sign().build()?)?;
        builder.append_extension(
            SubjectKeyIdentifier::new().build(&builder.x509v3_context(Some(issuer), None))?,
        )?;
        builder.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&builder.x509v3_context(Some(issuer), None))?,
        )?;

        let issuer_name = issuer
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .into_iter()
            .next()
            .map_or_else(
                || "?".to_string(),
                |n| {
                    n.data()
                        .as_utf8()
                        .map_or_else(|_| "?".to_string(), |s| s.to_string())
                },
            );

        builder.append_extension(X509Extension::new_from_der(
            Asn1Object::from_str(Nid::INFO_ACCESS.short_name()?.as_ref())?.as_ref(),
            false,
            Asn1OctetString::new_from_bytes(
                AuthorityInfoAccessSyntax(vec![AccessDescription {
                    access_method: ID_AD_CA_ISSUERS,
                    access_location: GeneralName::UniformResourceIdentifier(Ia5String::new(
                        format!("test://{}", issuer_name).as_str(),
                    )?),
                }])
                .to_der()?
                .as_slice(),
            )?
            .as_ref(),
        )?)?;

        builder.set_issuer_name(issuer.subject_name())?;

        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", format!("{}.{}", name_str, authority_id).as_str())?;
        let name = name.build();
        builder.set_subject_name(name.as_ref())?;

        let key = Self::gen_keypair()?;
        builder.set_pubkey(key.as_ref())?;

        builder.sign(issuer_key, MessageDigest::sha256())?;
        Ok((builder.build(), key))
    }

    fn build_ee(
        name_str: &str,
        authority_id: &str,
        issuer: &X509Ref,
        issuer_key: &PKeyRef<Private>,
    ) -> CertificatePathGeneratorResult<(X509, PKey<Private>)> {
        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;

        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;

        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;

        builder.set_serial_number(Asn1Integer::from_bn(serial.as_ref())?.as_ref())?;

        builder.append_extension(BasicConstraints::new().critical().build()?)?;
        builder.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
        builder.append_extension(
            SubjectKeyIdentifier::new().build(&builder.x509v3_context(Some(issuer), None))?,
        )?;
        builder.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&builder.x509v3_context(Some(issuer), None))?,
        )?;

        let issuer_name = issuer
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .into_iter()
            .next()
            .map_or_else(
                || "?".to_string(),
                |n| {
                    n.data()
                        .as_utf8()
                        .map_or_else(|_| "?".to_string(), |s| s.to_string())
                },
            );

        builder.append_extension(X509Extension::new_from_der(
            Asn1Object::from_str(Nid::INFO_ACCESS.short_name()?.as_ref())?.as_ref(),
            false,
            Asn1OctetString::new_from_bytes(
                AuthorityInfoAccessSyntax(vec![AccessDescription {
                    access_method: ID_AD_CA_ISSUERS,
                    access_location: GeneralName::UniformResourceIdentifier(Ia5String::new(
                        format!("test://{}", issuer_name).as_str(),
                    )?),
                }])
                .to_der()?
                .as_slice(),
            )?
            .as_ref(),
        )?)?;

        builder.set_issuer_name(issuer.subject_name())?;

        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", format!("{}.{}", name_str, authority_id).as_str())?;
        let name = name.build();
        builder.set_subject_name(name.as_ref())?;

        let key = Self::gen_keypair()?;
        builder.set_pubkey(key.as_ref())?;

        builder.sign(issuer_key, MessageDigest::sha256())?;
        Ok((builder.build(), key))
    }

    pub fn build_cross(
        issuer: &X509Ref,
        issuer_key: &PKeyRef<Private>,
        target: &X509Ref,
    ) -> CertificatePathGeneratorResult<X509> {
        let mut builder = X509Builder::new()?;

        builder.set_version(2)?;

        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;

        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;

        builder.set_serial_number(Asn1Integer::from_bn(serial.as_ref())?.as_ref())?;

        builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        builder.append_extension(KeyUsage::new().critical().key_cert_sign().build()?)?;
        builder.append_extension(
            SubjectKeyIdentifier::new().build(&builder.x509v3_context(Some(issuer), None))?,
        )?;
        builder.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&builder.x509v3_context(Some(issuer), None))?,
        )?;

        builder.set_issuer_name(issuer.subject_name())?;
        builder.set_subject_name(target.subject_name())?;

        builder.set_pubkey(target.public_key()?.as_ref())?;

        builder.sign(issuer_key, MessageDigest::sha256())?;
        Ok(builder.build())
    }

    fn gen_keypair() -> Result<PKey<Private>, ErrorStack> {
        let nid = Nid::X9_62_PRIME256V1;
        let group = EcGroup::from_curve_name(nid)?;
        let key = EcKey::generate(&group)?;
        PKey::from_ec_key(key)
    }
}
