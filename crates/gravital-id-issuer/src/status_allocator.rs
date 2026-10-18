//! Asignador de índices aleatorios para Token Status Lists (F7.T05, REQ-ISS-003, REQ-STAT-002, P-09).
//!
//! Trazabilidad:
//! - **REQ-STAT-002:** Las listas DEBEN tener un tamaño mínimo por perfil (>= 131.072 entradas)
//!   y asignar índices aleatoriamente.
//! - **REQ-ISS-003:** El emisor DEBE gestionar listas de estado y su asignación.
//! - **P-09 / REQ-PRIV-001:** Asignación no secuencial e impredecible para prevenir correlación
//!   temporal o rastreo del orden de expedición de credenciales.
//! - **INV-10 / INV-11:** Sin pánicos, aritmética comprobada, CSPRNG inyectado (`Rng`).

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use gravital_id_crypto::Rng;
use gravital_id_status::MIN_STATUS_LIST_ENTRIES;
use gravital_id_types::{ErrorCode, GidError};

/// Asignador de índices aleatorios sin colisión sobre el espacio de una Token Status List.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusIndexAllocator {
    capacity: usize,
    allocated_count: usize,
    bitmap: Vec<u64>,
}

impl StatusIndexAllocator {
    /// Construye un nuevo asignador para la capacidad indicada.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedStatusList`] si `capacity < MIN_STATUS_LIST_ENTRIES` (REQ-STAT-002).
    pub fn new(capacity: usize) -> Result<Self, GidError> {
        if capacity < MIN_STATUS_LIST_ENTRIES {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                format!(
                    "capacity {capacity} is lower than minimum allowed of {MIN_STATUS_LIST_ENTRIES} entries (REQ-STAT-002)"
                ),
            ));
        }

        let num_words = capacity.div_ceil(64);
        Ok(Self {
            capacity,
            allocated_count: 0,
            bitmap: vec![0u64; num_words],
        })
    }

    /// Capacidad total de entradas de la lista.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Número de entradas actualmente asignadas.
    #[must_use]
    pub fn allocated_count(&self) -> usize {
        self.allocated_count
    }

    /// Número de entradas libres disponibles para asignación.
    #[must_use]
    pub fn available_count(&self) -> usize {
        self.capacity.saturating_sub(self.allocated_count)
    }

    /// Indica si la lista ha alcanzado el 100% de ocupación.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.allocated_count >= self.capacity
    }

    /// Retorna una referencia de sólo lectura a las palabras de 64 bits del bitmap.
    #[must_use]
    pub fn bitmap(&self) -> &[u64] {
        &self.bitmap
    }

    /// Asigna de forma uniforme y aleatoria un índice libre sin reemplazo (REQ-STAT-002, P-09).
    ///
    /// # Errores
    /// - [`ErrorCode::StatusIndexOutOfRange`] si la lista no tiene entradas libres.
    /// - [`ErrorCode::InsufficientEntropy`] si el generador CSPRNG falla.
    pub fn allocate_random<R: Rng>(&mut self, rng: &R) -> Result<u64, GidError> {
        let available = self.available_count();
        if available == 0 {
            return Err(GidError::new(
                ErrorCode::StatusIndexOutOfRange,
                format!(
                    "status list capacity of {} entries has been completely exhausted",
                    self.capacity
                ),
            ));
        }

        // Muestreo uniforme en [0, available) sin sesgo de módulo
        let k = sample_uniform_index(available, rng)?;

        // Localizar el k-ésimo bit en 0 a través de los words del bitmap
        let mut remaining = k;
        for (word_idx, word) in self.bitmap.iter_mut().enumerate() {
            let base_index = word_idx.saturating_mul(64);
            let bits_in_word = if base_index.saturating_add(64) <= self.capacity {
                64
            } else {
                self.capacity.saturating_sub(base_index)
            };

            let zeros_in_word = count_zeros_in_word(*word, bits_in_word);
            if remaining < zeros_in_word {
                let bit_pos = find_kth_zero_in_word(*word, bits_in_word, remaining)?;
                *word |= 1u64 << bit_pos;
                self.allocated_count = self.allocated_count.saturating_add(1);
                let global_index = (base_index as u64).saturating_add(bit_pos as u64);
                return Ok(global_index);
            }
            remaining = remaining.saturating_sub(zeros_in_word);
        }

        Err(GidError::new(
            ErrorCode::StatusIndexOutOfRange,
            "failed to locate free status index in bitmap",
        ))
    }

    /// Libera un índice previamente asignado (p. ej. si la emisión de la credencial falló).
    ///
    /// # Errores
    /// [`ErrorCode::StatusIndexOutOfRange`] si `index >= capacity`.
    pub fn release(&mut self, index: u64) -> Result<(), GidError> {
        let cap_u64 = u64::try_from(self.capacity).unwrap_or(u64::MAX);
        if index >= cap_u64 {
            return Err(GidError::new(
                ErrorCode::StatusIndexOutOfRange,
                format!(
                    "status index {index} is out of range for capacity {}",
                    self.capacity
                ),
            ));
        }

        let word_idx = (index >> 6) as usize;
        let bit_pos = (index & 63) as u32;

        let Some(word) = self.bitmap.get_mut(word_idx) else {
            return Err(GidError::new(
                ErrorCode::StatusIndexOutOfRange,
                "internal bitmap index out of bounds",
            ));
        };

        let mask = 1u64.checked_shl(bit_pos).unwrap_or(0);
        if (*word & mask) != 0 {
            *word &= !mask;
            self.allocated_count = self.allocated_count.saturating_sub(1);
        }

        Ok(())
    }

    /// Marca manualmente un índice como asignado.
    ///
    /// # Errores
    /// [`ErrorCode::StatusIndexOutOfRange`] si `index >= capacity`.
    pub fn mark_allocated(&mut self, index: u64) -> Result<(), GidError> {
        let cap_u64 = u64::try_from(self.capacity).unwrap_or(u64::MAX);
        if index >= cap_u64 {
            return Err(GidError::new(
                ErrorCode::StatusIndexOutOfRange,
                format!(
                    "status index {index} is out of range for capacity {}",
                    self.capacity
                ),
            ));
        }

        let word_idx = (index >> 6) as usize;
        let bit_pos = (index & 63) as u32;

        let Some(word) = self.bitmap.get_mut(word_idx) else {
            return Err(GidError::new(
                ErrorCode::StatusIndexOutOfRange,
                "internal bitmap index out of bounds",
            ));
        };

        let mask = 1u64.checked_shl(bit_pos).unwrap_or(0);
        if (*word & mask) == 0 {
            *word |= mask;
            self.allocated_count = self.allocated_count.saturating_add(1);
        }

        Ok(())
    }

    /// Consulta si un índice ya está asignado.
    #[must_use]
    pub fn is_allocated(&self, index: u64) -> bool {
        let cap_u64 = u64::try_from(self.capacity).unwrap_or(u64::MAX);
        if index >= cap_u64 {
            return false;
        }

        let word_idx = (index >> 6) as usize;
        let bit_pos = (index & 63) as u32;
        let mask = 1u64.checked_shl(bit_pos).unwrap_or(0);

        self.bitmap
            .get(word_idx)
            .map(|&w| (w & mask) != 0)
            .unwrap_or(false)
    }
}

/// Muestrea un entero uniforme en `[0, limit)` sin sesgo de módulo usando el RNG inyectado.
fn sample_uniform_index<R: Rng>(limit: usize, rng: &R) -> Result<usize, GidError> {
    if limit == 0 {
        return Err(GidError::new(
            ErrorCode::StatusIndexOutOfRange,
            "limit is zero",
        ));
    }
    if limit == 1 {
        return Ok(0);
    }

    let m = limit as u64;
    let rem = u64::MAX
        .checked_rem(m)
        .ok_or_else(|| GidError::new(ErrorCode::StatusIndexOutOfRange, "modulo overflow"))?;
    let threshold = u64::MAX.wrapping_sub(rem);

    let mut buf = [0u8; 8];
    loop {
        rng.fill_bytes(&mut buf)?;
        let val = u64::from_le_bytes(buf);
        if val < threshold {
            let selected = val.checked_rem(m).ok_or_else(|| {
                GidError::new(ErrorCode::StatusIndexOutOfRange, "modulo overflow")
            })?;
            return usize::try_from(selected).map_err(|_| {
                GidError::new(ErrorCode::StatusIndexOutOfRange, "index exceeds usize")
            });
        }
    }
}

/// Cuenta el número de ceros en un `u64` considerando solo los primeros `valid_bits`.
fn count_zeros_in_word(word: u64, valid_bits: usize) -> usize {
    if valid_bits >= 64 {
        word.count_zeros() as usize
    } else {
        let mask = 1u64
            .checked_shl(valid_bits as u32)
            .unwrap_or(0)
            .wrapping_sub(1);
        let masked = word & mask;
        valid_bits.saturating_sub(masked.count_ones() as usize)
    }
}

/// Localiza la posición de bit (0..valid_bits) del k-ésimo bit en cero en un `u64`.
fn find_kth_zero_in_word(word: u64, valid_bits: usize, mut k: usize) -> Result<usize, GidError> {
    let limit = valid_bits.min(64);
    for bit in 0..limit {
        if (word & (1u64 << bit)) == 0 {
            if k == 0 {
                return Ok(bit);
            }
            k = k.saturating_sub(1);
        }
    }
    Err(GidError::new(
        ErrorCode::StatusIndexOutOfRange,
        "k-th zero not found in word range",
    ))
}
