import crypto, { diffieHellman } from 'crypto'
class DiffieHellman
{
    constructor()
    {
        this.primo = BigInt("0x"+"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF")
        this.gerador = 2n;
    }
    generateSecureKey()
    {
        const SECURE_TOKEN = BigInt("0x" + crypto.randomBytes(256).toString('hex'));
        this.secureKey = SECURE_TOKEN;
        return this;
    }
    generatePublicKey()
    {
        const PUBLIC_KEY = this.modPow(this.gerador, this.secureKey, this.primo)
        this.publicKey = PUBLIC_KEY;
        return this
    }
    mutualSecret(otherPublicKey)
    {
        const MUTUAL_VALUE = this.modPow(otherPublicKey, this.secureKey, this.primo)
        this.mutualValue = MUTUAL_VALUE
        return this;
    }
    modPow(x, n, m)
    {
        if (n === 0n) 
        {return 1n}
        if ((n & 1n) === 0n)
        {return this.modPow((x*x) %(m), n >> 1n, m) % m}
        return x*this.modPow((x*x) % (m),(n-1n) >> 1n, m) %m
    }
    hex()
    {
        const HEXED_MUTUAL_VALUE = this.mutualValue.toString(16);
        return HEXED_MUTUAL_VALUE
    }
}
export default DiffieHellman;