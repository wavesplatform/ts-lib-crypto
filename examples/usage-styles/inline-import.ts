import { address, publicKey, privateKey, keyPair } from '@waves/ts-lib-crypto'

const seed = 'secret seed'

address(seed) // 3P6z9d7iNzpF2JDwe4coWMgwE8SuTr67Wgp

publicKey(seed) // Fjyw5xkkJn97q8v2CRYFwwjjUfTUngu7B4vPr2aeYUuj

privateKey(seed) // G5vK6wVrqoUdcM2v7q716KUbe1xNnkEmUxQnPKEySpjd

keyPair(seed) // { publicKey: 'Fjyw5xkkJn97q8v2CRYFwwjjUfTUngu7B4vPr2aeYUuj', privateKey: 'G5vK6wVrqoUdcM2v7q716KUbe1xNnkEmUxQnPKEySpjd' }
