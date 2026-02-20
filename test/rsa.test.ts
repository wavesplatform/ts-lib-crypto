import {stringToBytes} from '../src/conversions/string-bytes'
import {pemToBytes, rsaKeyPair, rsaKeyPairSync, rsaSign, rsaVerify} from '../src/crypto/rsa'
import {base64Decode, base64Encode} from '../src/conversions/base-xx'
import {RSADigestAlgorithm} from '../src'
import {expect, test} from 'vitest'

test('Should get correct rsa signature', () => {
    const pair = rsaKeyPairSync()
    const msg = 'hello world'
    const msgBytes = stringToBytes(msg)
    const signature = rsaSign(pair.rsaPrivate, msgBytes)
    const valid = rsaVerify(pair.rsaPublic, msgBytes, signature)
    expect(valid).toBe(true)
})

test('Should get correct rsa signature with async keypair generation', async () => {
    const pair = await rsaKeyPair()
    const msg = 'hello world'
    const msgBytes = stringToBytes(msg)
    const signature = rsaSign(pair.rsaPrivate, msgBytes)
    const valid = rsaVerify(pair.rsaPublic, msgBytes, signature)
    expect(valid).toBe(true)
})


test('Should get correct rsa md5 signature with async keypair generation', async () => {
    const pair = await rsaKeyPair()
    const msg = 'hello world'
    const msgBytes = stringToBytes(msg)
    const signature = rsaSign(pair.rsaPrivate, msgBytes, 'MD5')
    const valid = rsaVerify(pair.rsaPublic, msgBytes, signature, 'MD5')
    expect(valid).toBe(true)
})

test('all possible hashes', async () => {
    const testData = [
        {
            alg: 'MD5',
            sig: 'kHOfaGcMkCSaVBwwyg/yy0IrYM3wntSh6/AxfdXDWyGgtxlOoeMi45Btw71hk8a+M2xCQ4FgTu2s3lWbYSTk3qf+hDOgRqOoKDoehAwtMC+DH/d/kcgArtnf9g13D4gbpWrcjb5M9Q6fNcPUfZDT6U13exh6rbjKGdpNCun2DqHzpUUUn96Jkc7XYXQwyEN8IU0J5Ez38dqlyDEvuRykjz/ABd/tQxp1IivVZ9OgAJttVlfAmmYCHPSSQfXAQk1w4fLremHqolQJGZzDCfKkqucni/BdWnMXJikI63y0u1++3Jnipb93PrfmLlGxWinwybD3O9oKiZ2SigHy5/t6eA=='
        },
        {
            alg: 'SHA1',
            sig: 'r06p9Zmdx+tJQYS2rDq4XLY4TZFofovPsq94gAkI4yCCBIQg7I+pkuixOONisnJZmItUWF9vvo+AGBTSDHDQWcTiVWLXD49ynlEG0GOS/W9zsT7KWYRwaaulXL7PFHSDC87OcuS2n0KEivM3K20QhcC+X/cNR5c6vJ2nmuAE/3xU1qlnMm/bUQYicuQOD0gKLb1BuVqFAZ/KQfKiuzdOoX9Pkg135qAygGSRRFIhJ67kb2lRpqeFS4FgHqc6Cm3oINDxx9MZTZ/DZnaqAByABbAIQhPrZeekg3Ysj8FoOvoxZGpvzb5cbjO6akV+aHnqOcOKksl/h5EKy2BjfNJpWA=='
        },
        {
            alg: 'SHA256',
            sig: 'AD/Q/AjmUUYlEec3LbBBNA+R8A+hlHyZoQs5BUuawJRqF0ROeJZLXktSegO8q6v+/W5yBRwuSbVSTyb/vtvvM0Qr8ayhKNpcF0unYtILO6g0farJGMU21Ne0I5nNknRveLmXY6itatba+3OU510HtZWmXo+y8qXNEp2VRI6Qpz2hzl1xt9qg8/psuAPNpk1OpFqShyh9lHNkwFQYJ2lDnoMkDWFof4SojTYAvL01sRtFGwjMb+K71QvGH0RX1FdGId/tubmFQRfMJuVpZkGgyZ/8PD245MkxbIJCAKraFst5n0Wi6wx++CT31fU4qLGYdaW3MW3h9zPPUV9RLJfeDQ=='
        },
        {
            alg: 'SHA384',
            sig: 'RXjxfAhg4f4G/UkRoyxnCTTKkME2ceTjQJJEgtL7O19srM3yFFqY2cqVFIFpOJBEQ+4KdncGZeQZmsHQrXfq5U8O9rZi9ugURKnG07l/hjvU6UqUJfWYCY31rEQUpURcH00GNmIUu8wQwFmTJT1LHao0tByAP01N7VJ2JSTzHbpb/buQh27AyIKoH8JibT5qQMS8LAf/m+Jxr0nGFyLd0KwV+YAs1TUfmOPSR15VeyN3qmL5PVB4j5tHXpa0fVq9ALVrvKyIuQDVX0w1L6KMcy+Y6tz3eBZrs+V7Jf5dEYe2+JXTxnAZU1c55DMIBCvPly76wYpL8w8XUA5WyJCw8w=='
        },
        {
            alg: 'SHA512',
            sig: 'swZmWD0MEXOm+pR9Xf3vP674doW9HgLxK8ntVyhUmrKsWc9GoCeX5Q3PgvVhkQ2lOA8GXZ1tXdrx6syfF5DZqBEiBASYyozL/KOd8C2r7oKIXeS1S6JzdwWiTxSD+PBpiMwBEbxj91tLKjrvcTCfzByCfNZdYv+/mi5Dxs/0wS6rdj62m5diUTy5MuY1NwC5E0OKShie0olyikDTflSUNMmiYjmykKW0xuXKJXsdOCO2DsqPCihRN2CeHsWXZZRJc8mPWPfqBElVGzJGzOpGDT4sfi8c9EuwFPsjUafB/2yrb2es5IsueSg/scqGmAxYZ+DpUO3OCioXr8z/zt21PA=='
        },
        {
            alg: 'SHA3-224',
            sig: 'UkOMw6DQHfALpkP6ChWYTPQmj/80YWL6DpkUJHaFQWhXFxuU/9JgpQ3qC6N/qZTHTwlpVlV+19gLrfhC2JJjCmNEM1zyuDd2Tln8Ny8MHK+aF4UD8JDOqQCn39uR6CLXpSHVFXP8RRzWo3YbmLI5WMZL087aKjcMQU7Yc7ebVFFcNJZrz7d8ZsSzUrTvxpuBypxDJT+Z2HfFDNQAty/pi1B6FetC3vbB/CWRXCk7NEqgZHavd/VsE4GixaM+PcQtVFjPRNTZir0aZfLey9hoYFOQ5oYVLM/RtmCTwQzRrcjUZv9EiPlZWqvokl1fFXD0ENRpDEFZ1Or2cqtV0zqdOg=='
        },
        {
            alg: 'SHA3-256',
            sig: 'idpbJpjm3Yz2qgiqNuicDK4cR3VMzu12ny40lSGwAln5w38KJhWdjjlyHwEjDHg1hXKSNRwCrIeykPuIIP3Wn+8mo/CRBUgBHahuCb0YwdfeE0CjeAKsIWoR+VmY36Eeocbc+zCOKMfw6Ybs2BvVZlycJ3R3YkzrL6+fQqKyhtWjg/CgrIBZ0g7Uq0U2HR9vD94vFwdBT63Xcf1tRc5Wq1TaxgsfNLY7SPaHwdNwJvvi01YhCe5W2HCf7dpzP/hn5mxxdOSIfi+j1wtBy4v5jezCB7Nzf45ZQ7vdCmGP1SKjAHsTSdJxuQBMACselLOniDdCscIIAhTPx6cOdM6ZyQ=='
        },
        {
            alg: 'SHA3-384',
            sig: 'L1TR8izeM0yRnMX7l6eKonHNGUmAsQi7GMOOmFQTFNZg9omVYYlgzCwq1LmR1R8DPAN40ZN9V0peEkocFT7zhLWLKAnE5YXBrm1iwMsIBK3WKLt2p7aknz1UwlGRZWlTlpPoOryYA0rgX4v8PnfYMjixck9Y5nPbl8+x/clnVzWEpCdeFw5wWFzskeFnXjAYaVVB0jtY3m8pKj+ZxCdU3sRtL3Ev8+wtRmW+h9BEicWYu98NqTAMH2TlGz/S3sq5IXl0XDau1ahwEj4QXp+B87JyR290yx87yi6KFcux7zkc+bfge9+pjZjDXO5LBao2jqvAuiDJ9PW96eUbbIq+XQ=='
        },
        {
            alg: 'SHA3-512',
            sig: 'pvPNCpOhu3Ju0VRR0tW1rwb5E6Px39xKZQVxKxdNrboJKhUmkDxEq8mm1EynbS8KshsB5YsbGmSpaDX+THKxlllDl0gHWJu54MV+Bh/HegvdorkrbPBzivFdiLj/ecY6Vc1HMcUd9mGvYlQ//fcOKvs8oGOK1Z2TE2ojKyuC/8Bsx/M29uRnBRUIh9nXD7eSAiui92NkNfCXjes7RLed6jO/kYbQw7Tl6h1hWoYHCBU39qJTK0NKV8U4/wI9A7tGDXfEbA51ulYS0XaYOUf7EqT/Aq+GV5w7CxOsc8P2B0h6YVLzUUHSia7CB6DYWkhk/v3ZC5qHxT92VOnC9715ag=='
        },
    ]
    const msg = base64Decode('aGVsbG8gd29ybGQ=')
    const pk = base64Decode('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt5IE7IAnSq7uK8FknxfEm2OtPvFOQlVy4F9arLp0PmhIRkDMpk7nWu3aNn6NBYX4kiigOLBhRDwNAZTJXnCjS8FQ/trZRo7oANiCX9kKwJZKQQCjLS0KSRWQWunDF7l9EUhTwb3QzhdSvYJLy3lOk90ZPB+36YvHooFx8oLIJimJhgbPXL95Yk6i+wh32Zhda616+9q/EftA5I4emJZRFLareSXM/MR03IFjYdh4S7LH+OPr94IQY/26Pt5HmS0X4W500HjxEp1vF8Irx3GYiF6Abk7JK5Gyf6W8ApEfAofj0s8qfLfHhH4JHg/QwW4NSd1NrhRMov2H7v31BVsRgwIDAQAB')

    testData.forEach(({alg, sig}) => {
        expect(rsaVerify(pk, msg, base64Decode(sig), alg as RSADigestAlgorithm)).toBe(true)
    })
})

test('Should get correct rsa signature sha3 message digest', async () => {

    const rsaPublic = base64Decode('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsoF++eHcQwJ6gtPcxHEMAmVTVmpyRrUrxsCQV3oeNu+EiMC45WTDHs5iTEaVgneDOhJ71CmgzJ1HvxRjSmuRtP29M/9HDQOtZjLDKGY+UvroJxjXQcJ/z/PDgTZv1pV6eX754vb+h1z600Vy8MNCoY1P2D36i9v4oN5vnVnHhdrT7h6zU7IyW4UW9arRBZe3K0JXzTLOx+nSxnoFuOb6e5Ruv7sRMZPIirLHM6hUx3eOJP3AWo/B6vRvqMNqXqpSiqDQazJqp8PVljOHsQUpHpx52+/+lzRGREERNirQF7Q+C8gUnFo9B2mRg02j0g8o2TFDBVn+HLQ0NFPQlrc2gQIDAQAB')
    const rsaPrivate = base64Decode('MIIEogIBAAKCAQEAsoF++eHcQwJ6gtPcxHEMAmVTVmpyRrUrxsCQV3oeNu+EiMC45WTDHs5iTEaVgneDOhJ71CmgzJ1HvxRjSmuRtP29M/9HDQOtZjLDKGY+UvroJxjXQcJ/z/PDgTZv1pV6eX754vb+h1z600Vy8MNCoY1P2D36i9v4oN5vnVnHhdrT7h6zU7IyW4UW9arRBZe3K0JXzTLOx+nSxnoFuOb6e5Ruv7sRMZPIirLHM6hUx3eOJP3AWo/B6vRvqMNqXqpSiqDQazJqp8PVljOHsQUpHpx52+/+lzRGREERNirQF7Q+C8gUnFo9B2mRg02j0g8o2TFDBVn+HLQ0NFPQlrc2gQIDAQABAoIBADF2kKjNXSt0VF5MNrB4YsuHKECZ3nCZYzf/w/95Z0XxuNfsD1ABS9ANgE+Cf4tXcpV06bswjc4lBux7ycelZwqwBO2TnyyMCFB5YHqhWkPEIvAygfNG4gPNmC8F1pevc/CWrseliYIY0agZZnAwqxX5Alb5VaPLoGlzOZpwdkkwkySXrr+VH2FKJeR2koq/y5fcO/bVVcu4j4mkXFQof0vsBSYRf4XVO8r80hWf2Ys6MVL2gcNAtWRZt7XGLfKOOm7/v7x9r1C1ajqfQVQBpk8QHlGmcGTMedPTkih8iere1oo3qNJl8xScMfAvGg7QMTlLICgfP/SEzzoQQ3AvO8ECgYEA5XQgpQJRQcMxKhs2DWi1N9HPv1plE7o90laPs+F5MtOn8Xwt2TTrAIL3kJ4nG/mBL692rdDzODBYOIFrx4UiHxB2jWamvoq1e9JsZKLwYAnb5rLdqmO9e3qitePxL8dPJOh9QYpuMDgawDFNb0yMpN0LlQsTF92pJktDLDDYaM8CgYEAxyhqf6reIpOuuIuQLrsTWkBNGaVPBMsoWNJtDg5lKQgTCxsVmRiPfyyZpb76lHKPysN1L/J1K5peeFhRCu5WK9j6dn8OU0TpboPQN07/cDQ9HZ+k6HR3fPfkpOgCVRnp7XqbE+MGXLs+fFa5AyfDBcS2k1EfUG1wf9RSUAkhn68CgYANWY1QrGrX3ahtn7msXAw3HDDvHC5HUI2qQDkKKTMo/uGFjkkImyiVFgmbU2hJG2IlyRqpkD+mZEGtv/HqYNeUYRvUrEVFTsKyWpLN5CECJXCy4nM9J6Jtnbv7wzBULE9xgUlQV+KDUbBUwEmWESkZqnazDDrnJ5Fg1f4pgwoERwKBgBnJq/CYCWdkxAz1VVgXtSvMg688bnzqaXEG3kQhrQuhFgYsHaHTQlFvTv3dOskaBHB22qe4t19L/8uJdAT8U4Ad+mB5lztFAwziWIWw3vaCbR922n2XBxnRZ3PK7vJiBp5Pb+ElVl+Ph0nGWPKFpYULsbBloq5hXV3P+lCOviHVAoGAJfD5s14oil6H4xDDPZMlELOpiuJQFyiIzyU19xR1N3QkyQb/fHlVIdiG5tMHpKaCVd0RryR77sRU3VVxpaYdJkLJQ+xkhwjqOZjyyxw3prO39e2m80s4jddHKKPJ1Bapxu4vY1qR7w0ptgKpxMOQTERcyuMmA4KvDgduW0q9/G0=')
    const msg = 'hello world'
    const msgBytes = stringToBytes(msg)
    const signature = rsaSign(rsaPrivate, msgBytes, 'SHA3-256')
    const valid = rsaVerify(rsaPublic, msgBytes, signature, 'SHA3-256')
    expect(valid).toBe(true)
})

test('Should get hardcoded signature', () => {
    const hardcodedSignature = 'yBZe9REcRPrDFSvB7iMl8uIzMGAAD/rqKpO0r8e2e9UziShAR3w96IUP+yC1N+Ape6EjeTyHbsHuKTNID/fqaA=='
    const msg = 'hello world'
    const privatePem = '-----BEGIN RSA PRIVATE KEY-----\n' +
        'MIIBOwIBAAJBAOoxJRf+ya3C6VR2S26WgIbDmIh7M5DGSjIi4mUJoD0c2bsmyI8/\n' +
        'BelIwRbqnETzGI+ONX+j58o6hvHnyR1XuS8CAwEAAQJABIcMs4kOdxiEkEh1Lt8j\n' +
        '/vb7FPBkz9C1kICSJefovCWwLCV05XORS3+4rP35AYpQIsksyBLxr1tcMt+fBgMM\n' +
        'OQIhAPcTZ7wYmcDHyN/4q8b6WJQ6CUAOTT6aVuqTwLpVeDGVAiEA8qab4g0Upukf\n' +
        'qtLzd9b3H0m80ANGi6BsSa5nVMPRVrMCIDupGuZnhlDvrQiwEkKU1ujL7snh6jMQ\n' +
        'r6YrEWGtG73VAiEArSEDB/6dRZn/5jotTMwr9j7+YMx1gRotKUUupOQycNECIQCh\n' +
        'HEpECtXjRr4z7Ef3pq4NRSymNtdlsjpGFYTLCm5PpQ==\n' +
        '-----END RSA PRIVATE KEY-----\n'

    const privateBytes = pemToBytes(privatePem)
    const msgBytes = stringToBytes(msg)
    const signature = base64Encode(rsaSign(privateBytes, msgBytes))
    expect(hardcodedSignature).toEqual(signature)
})


