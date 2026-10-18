package pa.gravital.id

import android.nfc.cardemulation.HostApduService
import android.os.Bundle

/**
 * Servicio Android Host Card Emulation (HCE) para el protocolo ISO/IEC 7816-4 `GID-APDU`
 * (`ADR-0022`, `PROTOCOL.md §7.4`, `REQ-PROX-001`, `REQ-PROX-006`).
 *
 * Nunca responde con credenciales si la wallet no ha sido explícitamente armada
 * por el titular durante la ventana activa (`SW=6985` ConsentPending).
 */
class GravitalHceService : HostApduService() {
    companion object {
        @Volatile
        var isArmedForTap: Boolean = false

        // SW=6985 (ConsentPending / GID-E8004)
        private val SW_CONSENT_PENDING = byteArrayOf(0x69.toByte(), 0x85.toByte())
    }

    override fun processCommandApdu(commandApdu: ByteArray?, extras: Bundle?): ByteArray {
        if (!isArmedForTap || commandApdu == null) {
            return SW_CONSENT_PENDING
        }
        // El puente MethodChannel("pa.gravital.id/nfc_hce") delega la máquina de estados GID-APDU.
        return SW_CONSENT_PENDING
    }

    override fun onDeactivated(reason: Int) {
        isArmedForTap = false
    }
}
