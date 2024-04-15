use md5::{Digest, Md5};

pub struct EvpKDF {
    key_size: usize,
    iterations: usize,
}

impl EvpKDF {
    /**
     * 创建一个新的 EvpKDF 实例
     * @param key_size 密钥长度     128/32
     * @param iterations 迭代次数   1
     */
    pub fn new(key_size: usize, iterations: usize) -> Self {
        EvpKDF {
            key_size,
            iterations,
        }
    }

    pub fn compute(&self, password: &[u8], salt: &[u8]) -> Vec<u8> {
        let mut derived_key = vec![];
        let mut hasher = Md5::new();
        let mut block = vec![];
        let iterations = self.iterations;
        while derived_key.len() < self.key_size {
            if !block.is_empty() {
                hasher.update(&block);
            }
            hasher.update(password);
            hasher.update(salt);

            block = hasher.clone().finalize().to_vec();
            hasher.reset();
            for _ in 1..iterations {
                hasher.update(&block);
                block = hasher.clone().finalize().to_vec();
                hasher.reset();
            }
            derived_key.extend_from_slice(&block);
        }

        derived_key
    }
}
