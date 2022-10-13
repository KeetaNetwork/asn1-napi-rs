const { existsSync, readFileSync } = require('fs')
const { join } = require('path')

const { platform, arch } = process

let nativeBinding = null
let localFileExisted = false
let loadError = null

function isMusl() {
  // For Node 10
  if (!process.report || typeof process.report.getReport !== 'function') {
    try {
      return readFileSync('/usr/bin/ldd', 'utf8').includes('musl')
    } catch (e) {
      return true
    }
  } else {
    const { glibcVersionRuntime } = process.report.getReport().header
    return !glibcVersionRuntime
  }
}

switch (platform) {
  case 'android':
    switch (arch) {
      case 'arm64':
        localFileExisted = existsSync(
          join(__dirname, 'asn1-napi-rs.android-arm64.node'),
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./asn1-napi-rs.android-arm64.node')
          } else {
            nativeBinding = require('./asn1-napi-rs-android-arm64/asn1-napi-rs-android-arm64.node')
          }
        } catch (e) {
          loadError = e
        }
        break
      case 'arm':
        localFileExisted = existsSync(
          join(__dirname, 'asn1-napi-rs.android-arm-eabi.node'),
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./asn1-napi-rs.android-arm-eabi.node')
          } else {
            nativeBinding = require('./asn1-napi-rs-android-arm-eabi/asn1-napi-rs-android-arm-eabi.node')
          }
        } catch (e) {
          loadError = e
        }
        break
      default:
        throw new Error(`Unsupported architecture on Android ${arch}`)
    }
    break
  case 'win32':
    switch (arch) {
      case 'x64':
        localFileExisted = existsSync(
          join(__dirname, 'asn1-napi-rs.win32-x64-msvc.node'),
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./asn1-napi-rs.win32-x64-msvc.node')
          } else {
            nativeBinding = require('./asn1-napi-rs-win32-x64-msvc/asn1-napi-rs-win32-x64-msvc.node')
          }
        } catch (e) {
          loadError = e
        }
        break
      case 'ia32':
        localFileExisted = existsSync(
          join(__dirname, 'asn1-napi-rs.win32-ia32-msvc.node'),
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./asn1-napi-rs.win32-ia32-msvc.node')
          } else {
            nativeBinding = require('./asn1-napi-rs-win32-ia32-msvc/asn1-napi-rs-win32-ia32-msvc.node')
          }
        } catch (e) {
          loadError = e
        }
        break
      case 'arm64':
        localFileExisted = existsSync(
          join(__dirname, 'asn1-napi-rs.win32-arm64-msvc.node'),
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./asn1-napi-rs.win32-arm64-msvc.node')
          } else {
            nativeBinding = require('./asn1-napi-rs-win32-arm64-msvc/asn1-napi-rs-win32-arm64-msvc.node')
          }
        } catch (e) {
          loadError = e
        }
        break
      default:
        throw new Error(`Unsupported architecture on Windows: ${arch}`)
    }
    break
  case 'darwin':
    switch (arch) {
      case 'x64':
        localFileExisted = existsSync(
          join(__dirname, 'asn1-napi-rs.darwin-x64.node'),
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./asn1-napi-rs.darwin-x64.node')
          } else {
            nativeBinding = require('./asn1-napi-rs-darwin-x64/asn1-napi-rs-darwin-x64.node')
          }
        } catch (e) {
          loadError = e
        }
        break
      case 'arm64':
        localFileExisted = existsSync(
          join(__dirname, 'asn1-napi-rs.darwin-arm64.node'),
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./asn1-napi-rs.darwin-arm64.node')
          } else {
            nativeBinding = require('./asn1-napi-rs-darwin-arm64/asn1-napi-rs-darwin-arm64.node')
          }
        } catch (e) {
          loadError = e
        }
        break
      default:
        throw new Error(`Unsupported architecture on macOS: ${arch}`)
    }
    break
  case 'freebsd':
    if (arch !== 'x64') {
      throw new Error(`Unsupported architecture on FreeBSD: ${arch}`)
    }
    localFileExisted = existsSync(
      join(__dirname, 'asn1-napi-rs.freebsd-x64.node'),
    )
    try {
      if (localFileExisted) {
        nativeBinding = require('./asn1-napi-rs.freebsd-x64.node')
      } else {
        nativeBinding = require('./asn1-napi-rs-freebsd-x64/asn1-napi-rs-freebsd-x64.node')
      }
    } catch (e) {
      loadError = e
    }
    break
  case 'linux':
    switch (arch) {
      case 'x64':
        if (isMusl()) {
          localFileExisted = existsSync(
            join(__dirname, 'asn1-napi-rs.linux-x64-musl.node'),
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./asn1-napi-rs.linux-x64-musl.node')
            } else {
              nativeBinding = require('./asn1-napi-rs-linux-x64-musl/asn1-napi-rs-linux-x64-musl.node')
            }
          } catch (e) {
            loadError = e
          }
        } else {
          localFileExisted = existsSync(
            join(__dirname, 'asn1-napi-rs.linux-x64-gnu.node'),
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./asn1-napi-rs.linux-x64-gnu.node')
            } else {
              nativeBinding = require('./asn1-napi-rs-linux-x64-gnu/asn1-napi-rs-linux-x64-gnu.node')
            }
          } catch (e) {
            loadError = e
          }
        }
        break
      case 'arm64':
        if (isMusl()) {
          localFileExisted = existsSync(
            join(__dirname, 'asn1-napi-rs.linux-arm64-musl.node'),
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./asn1-napi-rs.linux-arm64-musl.node')
            } else {
              nativeBinding = require('./asn1-napi-rs-linux-arm64-musl/asn1-napi-rs-linux-arm64-musl.node')
            }
          } catch (e) {
            loadError = e
          }
        } else {
          localFileExisted = existsSync(
            join(__dirname, 'asn1-napi-rs.linux-arm64-gnu.node'),
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./asn1-napi-rs.linux-arm64-gnu.node')
            } else {
              nativeBinding = require('./asn1-napi-rs-linux-arm64-gnu/asn1-napi-rs-linux-arm64-gnu.node')
            }
          } catch (e) {
            loadError = e
          }
        }
        break
      case 'arm':
        localFileExisted = existsSync(
          join(__dirname, 'asn1-napi-rs.linux-arm-gnueabihf.node'),
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./asn1-napi-rs.linux-arm-gnueabihf.node')
          } else {
            nativeBinding = require('./asn1-napi-rs-linux-arm-gnueabihf/asn1-napi-rs-linux-arm-gnueabihf.node')
          }
        } catch (e) {
          loadError = e
        }
        break
      default:
        throw new Error(`Unsupported architecture on Linux: ${arch}`)
    }
    break
  default:
    throw new Error(`Unsupported OS: ${platform}, architecture: ${arch}`)
}

if (!nativeBinding) {
  if (loadError) {
    throw loadError
  }
  throw new Error(`Failed to load native binding`)
}

const {
  Asn1,
  Asn1Iterator,
  Asn1Encoder,
  BigIntToBuffer,
  BufferToBigInt,
  IntegerToBigInt,
  StringToBigInt,
  JStoASN1,
  ASN1toJS,
} = nativeBinding

module.exports.Asn1 = Asn1
module.exports.Asn1Iterator = Asn1Iterator
module.exports.Asn1Encoder = Asn1Encoder
module.exports.BigIntToBuffer = BigIntToBuffer
module.exports.BufferToBigInt = BufferToBigInt
module.exports.IntegerToBigInt = IntegerToBigInt
module.exports.StringToBigInt = StringToBigInt
module.exports.JStoASN1 = JStoASN1
module.exports.ASN1toJS = ASN1toJS
