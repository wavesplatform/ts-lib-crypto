import { address, publicKey, privateKey, keyPair } from '@waves/waves-crypto'

const seed = 'secret seed'

console.log(address(seed)) // 3P6z9d7iNzpF2JDwe4coWMgwE8SuTr67Wgp

console.log(publicKey(seed)) // Fjyw5xkkJn97q8v2CRYFwwjjUfTUngu7B4vPr2aeYUuj

console.log(privateKey(seed)) // G5vK6wVrqoUdcM2v7q716KUbe1xNnkEmUxQnPKEySpjd

console.log(keyPair(seed)) // { privateKey: 'G5vK6wVrqoUdcM2v7q716KUbe1xNnkEmUxQnPKEySpjd', publicKey: 'Fjyw5xkkJn97q8v2CRYFwwjjUfTUngu7B4vPr2aeYUuj' }

