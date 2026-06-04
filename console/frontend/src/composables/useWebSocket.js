import { ref, onUnmounted } from 'vue'

/**
 * Reusable WebSocket composable with auto-reconnect.
 *
 * @param {() => string} urlFn - Function returning the WebSocket URL
 *   (called on each connect attempt so it can reflect current route params).
 * @param {Object} opts
 * @param {(msg: Object) => void} opts.onMessage - Called for each parsed JSON message
 * @param {() => void} [opts.onOpen] - Called on connection open
 * @param {() => void} [opts.onClose] - Called on connection close (after reconnect decision)
 * @param {boolean} [opts.autoReconnect=true] - Reconnect on disconnect
 * @param {number} [opts.reconnectInterval=3000] - Reconnect delay in ms
 * @param {boolean} [opts.enabled=true] - Whether to auto-connect on mount
 */
export function useWebSocket(urlFn, {
  onMessage,
  onOpen,
  onClose,
  autoReconnect = true,
  reconnectInterval = 3000,
  enabled = true,
} = {}) {
  const isConnected = ref(false)
  let socket = null
  let reconnectTimer = null
  let intentionalClose = false

  function connect() {
    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
      return
    }
    intentionalClose = false

    const url = urlFn()
    if (!url) return

    socket = new WebSocket(url)

    socket.onopen = () => {
      isConnected.value = true
      onOpen?.()
    }

    socket.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        onMessage?.(msg)
      } catch (e) {
        console.error('WebSocket parse error:', e)
      }
    }

    socket.onclose = () => {
      isConnected.value = false
      socket = null
      onClose?.()

      if (autoReconnect && !intentionalClose) {
        reconnectTimer = setTimeout(connect, reconnectInterval)
      }
    }

    socket.onerror = (err) => {
      console.error('WebSocket error:', err)
      socket?.close()
    }
  }

  function close() {
    intentionalClose = true
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    if (socket) {
      socket.close()
      socket = null
    }
    isConnected.value = false
  }

  if (enabled) {
    connect()
  }

  onUnmounted(close)

  return { isConnected, connect, close }
}
