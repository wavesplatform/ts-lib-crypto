import { randomBytes, random } from '@waves/ts-lib-crypto'

const length = 3
console.log(randomBytes(length))             // Uint8Array [ 120, 46, 179 ]          
console.log(random(length, 'Array16'))       // [ 61736, 48261, 38395 ] 
console.log(random(length, 'Array32'))       // [ 406628961, 307686833, 2604847943 ]       
console.log(random(length, 'Array8'))        // [ 19, 172, 130 ]       
console.log(random(length, 'Buffer'))        // <Buffer db ff fb>       
console.log(random(length, 'Uint8Array'))    // Uint8Array [ 137, 85, 212 ]   
console.log(random(length, 'Uint16Array'))   // Uint16Array [ 35881, 51653, 55967 ]  
console.log(random(length, 'Uint32Array'))   // Uint32Array [ 698646076, 2957331816, 2073997581 ]    