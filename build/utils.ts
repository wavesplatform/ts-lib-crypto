import { mkdir, readdir, exists as ex, readFile, writeFile } from 'fs'
import { exec } from 'child_process'
import { resolve } from 'path'
import { ncp } from 'ncp'
import rimraf from 'rimraf'

export const p = (...path: string[]) => resolve(__dirname, ...path)

export const remove = (path: string): Promise<void> =>
  new Promise((resolve, reject) => rimraf(path, (err: any) => err ? reject(err) : resolve()))

export const copy = (src: string, dst: string): Promise<void> =>
  new Promise((resolve, reject) => ncp(src, dst, (err: any) => err ? reject(err) : resolve()))

export const exists = (path: string): Promise<boolean> =>
  new Promise((resolve, _) => ex(path, (exists) => resolve(exists)))

export const create = (path: string): Promise<void> =>
  new Promise((resolve, reject) =>
    exists(path).then(exists => !exists ? (mkdir(path, (err) => err ? reject(err) : resolve())) : resolve())
  )

export const run = (cmd: string, cwd?: string): Promise<string> =>
  new Promise((resolve, reject) => exec(cmd, { cwd }, (err, out) => err ? reject(err) : resolve(out)))

export const files = (path: string, filter: (file: string) => boolean = (_) => true): Promise<string[]> =>
  new Promise((resolve, reject) => readdir(path, (err, files) => err ? reject(err) : resolve(files.filter(filter))))

export const copyJson = (src: string, dst: string, overrideFields?: { [key: string]: any }): Promise<void> =>
  new Promise(((resolve, reject) => readFile(src, ((err, data) => {
    if (err) reject(err)
    const modified = { ...JSON.parse(data.toString()), ...overrideFields }
    writeFile(dst, JSON.stringify(modified, null, 2), err => err ? reject(err) : resolve())
  }))))

export const npmInstall = async (pkg: string, path: string) => {
  await run(`npm pack ${pkg}`, p(path))
  const tgz = (await files(p(path), f => f.startsWith(`${pkg}-`)))[0]
  await run(`tar zxvf ${tgz}`, p(path))
  await create(p(path, 'node_modules'))
  await copy(p(path, 'package'), p(path, `node_modules/${pkg}`))
  await remove(p(path, 'package'))
  await remove(p(path, tgz))
}

export interface Version {
  major: number
  minor: number
  patch: number
}

export const versionToString = (version: Version) => `${version.major}.${version.minor}.${version.patch}`

export const npmGetVersion = async (pkg: string): Promise<Version> => {
  const parts = (await run(`npm show ${pkg} version`)).trim().split('.')
  return {
    major: parseInt(parts[0]),
    minor: parseInt(parts[1]),
    patch: parseInt(parts[2]),
  }
}

