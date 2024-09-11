use crate::util::base64_encode;

pub fn with_sign(mut vec: Vec<u8>) -> Vec<u8> {
    if !vec.is_empty() && vec[0] >= 128 {
        vec.insert(0, 0x00);
    }
    vec
}

pub fn generate_ssh_string(e: &[u8], n: &[u8], comment: &str) -> String {
    let mut ssh_key = vec![];
    append_slice_with_len(&mut ssh_key, "ssh-rsa".as_bytes());
    append_slice_with_len(&mut ssh_key, &with_sign(e.to_vec()));
    append_slice_with_len(&mut ssh_key, &with_sign(n.to_vec()));
    format!("ssh-rsa {} {}", base64_encode(&ssh_key), comment)
}

pub fn append_slice_with_len(v: &mut Vec<u8>, s: &[u8]) {
    v.extend_from_slice(&(s.len() as u32).to_be_bytes()[..]);
    v.extend_from_slice(s);
}

pub trait SshVecWriter {
    fn write_bytes(&mut self, bytes: &[u8]);
    fn write_u32(&mut self, num: u32);
    fn write_string(&mut self, bytes: &[u8]);
}

impl SshVecWriter for Vec<u8> {
    fn write_bytes(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }

    fn write_u32(&mut self, num: u32) {
        self.write_bytes(&num.to_be_bytes());
    }

    fn write_string(&mut self, bytes: &[u8]) {
        self.write_u32(bytes.len() as u32);
        self.write_bytes(bytes);
    }
}
