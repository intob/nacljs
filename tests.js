window.runTests = function() {
    console.log("Running tests...")

    // Test the Nacl class
    test_Nacl_scalarMult()
    test_Nacl_scalarMult_base()
    test_Nacl_sign()
    test_Nacl_sign_open()

    // Test the SecretBox class
    test_SecretBox_constructor()
    test_SecretBox_open()

    // Test the Box class
    test_Box_constructor()
    test_Box_before()
    test_Box_open()

    // Test the KeyPair class
    test_KeyPair_constructor()
    test_KeyPair_fromSecretKey()

    console.log("All tests passed!")
}

// Test the Nacl class
function test_Nacl_scalarMult() {
    const nacl = new Nacl(() => new Uint8Array(32))
    const n = new Uint8Array(SCALARMULT_SCALARBYTES)
    const p = new Uint8Array(SCALARMULT_BYTES)
    const q = nacl.scalarMult(n, p)
    assert(q instanceof Uint8Array)
    assert(q.length === SCALARMULT_BYTES)
}

function test_Nacl_scalarMult_base() {
    const nacl = new Nacl(() => new Uint8Array(32))
    const n = new Uint8Array(SCALARMULT_SCALARBYTES)
    const q = nacl.scalarMult_base(n)
    assert(q instanceof Uint8Array)
    assert(q.length === SCALARMULT_BYTES)
}

function test_Nacl_sign() {
    const nacl = new Nacl(() => new Uint8Array(32))
    const msg = new Uint8Array([1, 2, 3])
    const secretKey = new Uint8Array(SIGN_SECRETKEYBYTES)
    const signedMsg = nacl.sign(msg, secretKey)
    assert(signedMsg instanceof Uint8Array)
    assert(signedMsg.length === msg.length + SIGN_BYTES)
}

function test_Nacl_sign_open() {
    const nacl = new Nacl(() => new Uint8Array(32))
    const msg = new Uint8Array([1, 2, 3])
    const keyPair = KeyPair.fromSecretKey(new Uint8Array(SIGN_SECRETKEYBYTES))
    const signedMsg = nacl.sign(msg, keyPair.secretKey)
    const openedMsg = nacl.sign_open(signedMsg, keyPair.publicKey)
    assert(openedMsg instanceof Uint8Array)
    assert(openedMsg.length === msg.length)
    assert(openedMsg.every((byte, i) => byte === msg[i]))
}

// Test the SecretBox class
function test_SecretBox_constructor() {
    const msg = new Uint8Array([1, 2, 3])
    const nonce = new Uint8Array(SECRETBOX_NONCELEN)
    const key = new Uint8Array(SECRETBOX_KEYLEN)
    const box = new SecretBox(msg, nonce, key)
    assert(box.c instanceof Uint8Array)
    assert(box.c.length === msg.length + SECRETBOX_BOXZEROLEN)
}

function test_SecretBox_open() {
    const msg = new Uint8Array([1, 2, 3])
    const nonce = new Uint8Array(SECRETBOX_NONCELEN)
    const key = new Uint8Array(SECRETBOX_KEYLEN)
    const box = new SecretBox(msg, nonce, key)
    const openedMsg = box.open(box.c, nonce, key)
    assert(openedMsg instanceof Uint8Array)
    assert(openedMsg.length === msg.length)
    assert(openedMsg.every((byte, i) => byte === msg[i]))
}

// Test the Box class
function test_Box_constructor() {
    const msg = new Uint8Array([1, 2, 3])
    const nonce = new Uint8Array(BOX_NONCEBYTES)
    const keyPair = new KeyPair()
    const box = new Box(msg, nonce, keyPair.publicKey, keyPair.secretKey)
    assert(box.secretBox instanceof SecretBox)
}

function test_Box_before() {
    const keyPair = new KeyPair()
    const sharedKey = Box.before(keyPair.publicKey, keyPair.secretKey)
    assert(sharedKey instanceof Uint8Array)
    assert(sharedKey.length === BOX_BEFORENMBYTES)
}

function test_Box_open() {
    const msg = new Uint8Array([1, 2, 3])
    const nonce = new Uint8Array(BOX_NONCEBYTES)
    const keyPair = new KeyPair()
    const box = new Box(msg, nonce, keyPair.publicKey, keyPair.secretKey)
    const openedMsg = box.open(box.secretBox.c, nonce, keyPair.publicKey, keyPair.secretKey)
    assert(openedMsg instanceof Uint8Array)
    assert(openedMsg.length === msg.length)
    assert(openedMsg.every((byte, i) => byte === msg[i]))
}

// Test the KeyPair class
function test_KeyPair_constructor() {
    const keyPair = new KeyPair()
    assert(keyPair.publicKey instanceof Uint8Array)
    assert(keyPair.publicKey.length === BOX_PUBLICKEYBYTES)
    assert(keyPair.secretKey instanceof Uint8Array)
    assert(keyPair.secretKey.length === BOX_SECRETKEYBYTES)
}

function test_KeyPair_fromSecretKey() {
    const secretKey = new Uint8Array(BOX_SECRETKEYBYTES)
    const keyPair = KeyPair.fromSecretKey(secretKey)
    assert(keyPair.publicKey instanceof Uint8Array)
    assert(keyPair.publicKey.length === BOX_PUBLICKEYBYTES)
    assert(keyPair.secretKey instanceof Uint8Array)
    assert(keyPair.secretKey.length === BOX_SECRETKEYBYTES)
    assert(keyPair.secretKey.every((byte, i) => byte === secretKey[i]))
}
