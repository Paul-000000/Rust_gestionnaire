use aes_gcm::aead::rand_core::RngCore;
use bincode::{Encode, de::Decoder, error::DecodeError};
use argon2::password_hash::{rand_core::OsRng as ArgonRng};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Salt {
    sel: [u8; 16]       
}



impl Salt {
    
    pub fn new() -> Self {
        
        let mut sel = [0u8; 16];
        ArgonRng.fill_bytes(&mut sel); // Génération aléatoire brute
        Self { sel }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.sel
    }
}



impl Encode for Salt {
    fn encode<E: bincode::enc::Encoder>(&self, encoder: &mut E) -> Result<(), bincode::error::EncodeError> {
        self.sel.encode(encoder)
    }
}

impl<C> bincode::Decode<C> for Salt 
where 
    [u8; 16]: bincode::Decode<C> 
{
    fn decode<D: Decoder<Context = C>>(decoder: &mut D) -> Result<Self, DecodeError> {
        
        let sel = <[u8; 16]>::decode(decoder)?;
        Ok(Salt { sel })
    }
}

impl serde::Serialize for Salt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let b64 = STANDARD.encode(self.sel);
        serializer.serialize_str(&b64)
    }
}

impl<'de> serde::Deserialize<'de> for Salt {

    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
    
        let bytes = STANDARD.decode(s)
            .map_err(|e| serde::de::Error::custom(format!("Erreur décodage Base64: {}", e)))?;
        
        let sel: [u8; 16] = bytes.try_into()
            .map_err(|_| serde::de::Error::custom("Le sel doit faire exactement 16 octets"))?;

        Ok(Salt { sel })
    }
}

impl<'de, C> bincode::BorrowDecode<'de, C> for Salt 
where 
    [u8; 16]: bincode::Decode<C> 
{ 
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(decoder: &mut D) -> Result<Self, DecodeError> {
        
        let sel = <[u8; 16]>::borrow_decode(decoder)?;

        Ok(Salt { sel: sel })
    }
}