// This is a workaround because dagre-d3 requires that you use stringified html for elements. We encode an object via a global onclick handler, and then decode outside

export function encode(object) {
  return encodeURIComponent(JSON.stringify(object))
}

export function decode(string) {
  return JSON.parse(decodeURIComponent(string))
}
