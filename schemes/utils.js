

export function encodeQuery(queryObject) {
  return Object.entries(queryObject)
    .filter(([_key, value]) => typeof value !== 'undefined')
    .map(
      ([key, value]) =>
        encodeURIComponent(key) +
        (value != null ? '=' + encodeURIComponent(value) : '')
    )
    .join('&')
}

export function normalizePath(path = '', ctx) {
  // Remove query string
  let result = path.split('?')[0]

  // Remove base path
  if (ctx && ctx.base) {
    result = result.replace(ctx.base, '/')
  }

  // Remove redundant / from the end of path
  if (result.charAt(result.length - 1) === '/') {
    result = result.slice(0, -1)
  }

  // Remove duplicate slashes
  result = result.replace(/\/+/g, '/')

  return result
}

export function urlJoin(...args) {
  return args
    .join('/')
    .replace(/[/]+/g, '/')
    .replace(/^(.+):\//, '$1://')
    .replace(/^file:/, 'file:/')
    .replace(/\/(\?|&|#[^!])/g, '$1')
    .replace(/\?/g, '&')
    .replace('&', '?')
}


const characters =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
export function randomString(length) {
  let result = ''
  const charactersLength = characters.length
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength))
  }
  return result
}



export function parseQuery(queryString) {
  const query = {}
  const pairs = queryString.split('&')
  for (let i = 0; i < pairs.length; i++) {
    const pair = pairs[i].split('=')
    query[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1] || '')
  }
  return query
}

export function getProp(
  holder,
  propName
) {
  if (!propName || !holder || typeof holder !== 'object') {
    return holder
  }

  if (propName in holder) {
    return holder[propName]
  }

  const propParts = Array.isArray(propName)
    ? propName
    : (propName + '').split('.')

  let result = holder
  while (propParts.length && result) {
    result = result[propParts.shift()]
  }

  return result
}

export function generateRandomString() {
  const array = new Uint32Array(28) // this is of minimum required length for servers with PKCE-enabled
  window.crypto.getRandomValues(array)
  return Array.from(array, (dec) => ('0' + dec.toString(16)).substr(-2)).join(
    ''
  )
}

