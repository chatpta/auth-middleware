class Keys {
    constructor( keys ) {
        this.privateKey = keys.privateKey;
        this.publicKey = keys.publicKey;
    }

    getPrivateKey() {
        return this.privateKey;
    }

    getPublicKey() {
        return this.publicKey;
    }
}

module.exports = Keys;
