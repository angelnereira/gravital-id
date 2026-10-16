// SPDX-License-Identifier: Apache-2.0 OR MIT
package id.gravital.spike;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.Signature;

/**
 * Minimal Java Card 3.0.5+ spike applet for F19.T13 (ADR-0024).
 *
 * Verifies:
 * - On-card NIST P-256 key generation where private key material never leaves the chip (REQ-CARD-001).
 * - Lifecycle state enforcement: PERSONALIZATION -> ACTIVE -> BLOCKED -> TERMINATED (REQ-CARD-002).
 * - CVM Level 0 (no PIN) vs Level 1 (OwnerPIN with retry counter, max 5 tries) (REQ-CARD-003).
 * - ECDH P-256 shared secret derivation + ECDSA-SHA256 signing for GID-APDU proximity sessions.
 */
public final class GidSpikeApplet extends Applet {

    private static final byte STATE_PERSONALIZATION = (byte) 0x01;
    private static final byte STATE_ACTIVE = (byte) 0x02;
    private static final byte STATE_BLOCKED = (byte) 0x03;
    private static final byte STATE_TERMINATED = (byte) 0x04;

    private static final byte CLA_PROPRIETARY = (byte) 0x80;
    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_GENERATE_KEY = (byte) 0x46;
    private static final byte INS_GET_RESPONSE = (byte) 0xC0;
    private static final byte INS_ENVELOPE = (byte) 0xC3;
    private static final byte INS_ACTIVATE = (byte) 0xDA;

    private static final byte PIN_TRY_LIMIT = (byte) 5;
    private static final byte PIN_MAX_SIZE = (byte) 8;

    private byte lifecycleState;
    private final OwnerPIN holderPin;
    private final KeyPair holderKeyPair;
    private final KeyAgreement ecdhAgreement;
    private final Signature ecdsaSigner;
    private final MessageDigest sha256;
    private final byte[] transientWorkspace;

    private GidSpikeApplet() {
        this.lifecycleState = STATE_PERSONALIZATION;
        this.holderPin = new OwnerPIN(PIN_TRY_LIMIT, PIN_MAX_SIZE);
        this.holderKeyPair = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);
        this.ecdhAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        this.ecdsaSigner = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        this.sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        this.transientWorkspace = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new GidSpikeApplet().register();
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            sendHolderHello(apdu);
            return;
        }
        if (lifecycleState == STATE_TERMINATED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buf = apdu.getBuffer();
        byte ins = buf[ISO7816.OFFSET_INS];

        switch (ins) {
            case INS_GENERATE_KEY:
                handleGenerateKey(apdu);
                break;
            case INS_ACTIVATE:
                handleActivate(apdu);
                break;
            case INS_VERIFY_PIN:
                handleVerifyPin(apdu);
                break;
            case INS_ENVELOPE:
                handleEnvelope(apdu);
                break;
            case INS_GET_RESPONSE:
                handleGetResponse(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void sendHolderHello(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        // Compact CBOR HolderHello: {1: [1], 2: 240, 3: 1, 4: false}
        byte[] hello = {(byte) 0xA4, 0x01, (byte) 0x81, 0x01, 0x02, 0x18, (byte) 0xF0, 0x03, 0x01, 0x04, (byte) 0xF4};
        Util.arrayCopyNonAtomic(hello, (short) 0, buf, (short) 0, (short) hello.length);
        apdu.setOutgoingAndSend((short) 0, (short) hello.length);
    }

    private void handleGenerateKey(APDU apdu) {
        if (lifecycleState != STATE_PERSONALIZATION) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        holderKeyPair.genKeyPair();
        ECPrivateKey priv = (ECPrivateKey) holderKeyPair.getPrivate();
        ECPublicKey pub = (ECPublicKey) holderKeyPair.getPublic();
        ecdhAgreement.init(priv);
        ecdsaSigner.init(priv, Signature.MODE_SIGN);

        // Export ONLY uncompressed SEC1 public point W (65 bytes); private scalar is never exported
        byte[] buf = apdu.getBuffer();
        short len = pub.getW(buf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private void handleActivate(APDU apdu) {
        if (lifecycleState != STATE_PERSONALIZATION) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        holderPin.update(buf, ISO7816.OFFSET_CDATA, (byte) lc);
        lifecycleState = STATE_ACTIVE;
    }

    private void handleVerifyPin(APDU apdu) {
        if (lifecycleState == STATE_BLOCKED || holderPin.getTriesRemaining() == 0) {
            lifecycleState = STATE_BLOCKED;
            ISOException.throwIt((short) 0x6983); // Authentication method blocked -> GID-E8006
        }
        byte[] buf = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (!holderPin.check(buf, ISO7816.OFFSET_CDATA, (byte) lc)) {
            byte tries = holderPin.getTriesRemaining();
            if (tries == 0) {
                lifecycleState = STATE_BLOCKED;
                ISOException.throwIt((short) 0x6983);
            }
            ISOException.throwIt((short) (0x63C0 | (tries & 0x0F)));
        }
    }

    private void handleEnvelope(APDU apdu) {
        if (lifecycleState != STATE_ACTIVE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        // P1 == 0x01 indicates Level 1 (sensitive claims requiring verified PIN)
        if (buf[ISO7816.OFFSET_P1] == (byte) 0x01 && !holderPin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED); // 6982 -> GID-E8005
        }
        // Compute SHA-256 over request and sign with on-card ECDSA P-256 key
        sha256.reset();
        sha256.doFinal(buf, ISO7816.OFFSET_CDATA, lc, transientWorkspace, (short) 0);
        short sigLen = ecdsaSigner.sign(
            transientWorkspace,
            (short) 0,
            (short) 32,
            transientWorkspace,
            (short) 32
        );
        Util.setShort(transientWorkspace, (short) 0, sigLen);
        ISOException.throwIt((short) (0x6100 | (sigLen & 0xFF)));
    }

    private void handleGetResponse(APDU apdu) {
        short sigLen = Util.getShort(transientWorkspace, (short) 0);
        if (sigLen <= 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        Util.arrayCopyNonAtomic(transientWorkspace, (short) 32, buf, (short) 0, sigLen);
        Util.setShort(transientWorkspace, (short) 0, (short) 0);
        apdu.setOutgoingAndSend((short) 0, sigLen);
    }
}
