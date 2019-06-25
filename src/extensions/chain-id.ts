import { TChainId, MAIN_NET_CHAIN_ID } from '../crypto/interface'
import { TEST_NET_CHAIN_ID } from '../crypto/interface'

export const ChaidId = {
  toNumber(chainId: TChainId): number {
    return (typeof chainId === 'string' ? chainId.charCodeAt(0) : chainId)
  },
  isMainnet(chainId: TChainId): boolean {
    return ChaidId.toNumber(chainId) === MAIN_NET_CHAIN_ID
  },
  isTestnet(chainId: TChainId): boolean {
    return ChaidId.toNumber(chainId) === TEST_NET_CHAIN_ID
  },
}