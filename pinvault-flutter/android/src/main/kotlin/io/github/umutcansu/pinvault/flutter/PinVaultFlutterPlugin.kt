package io.github.umutcansu.pinvault.flutter

import android.content.Context
import androidx.annotation.NonNull

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.EventChannel

import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.PinVaultConfig
import io.github.umutcansu.pinvault.ConfigApiBlock
import io.github.umutcansu.pinvault.HostPin
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.Request
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.Response

class PinVaultFlutterPlugin: FlutterPlugin, MethodCallHandler {
  private lateinit var channel : MethodChannel
  private lateinit var flutterPluginBinding: FlutterPlugin.FlutterPluginBinding
  private lateinit var context: Context
  private val activeSockets = mutableMapOf<String, WebSocket>()

  override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    this.flutterPluginBinding = flutterPluginBinding
    this.context = flutterPluginBinding.applicationContext
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "pinvault_flutter")
    channel.setMethodCallHandler(this)
  }

  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
    when (call.method) {
        "start" -> {
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    // TODO: Replace with full parsing from the dictionary
                    // We map the Dart Map to PinVaultConfig native builders here
                    val configMap = call.arguments as Map<String, Any>
                    
                    // Example mapping (Requires expanding for all properties):
                    val configBuilder = PinVaultConfig.Builder()
                    
                    val initResult = PinVault.start(context, configBuilder.build())
                    
                    launch(Dispatchers.Main) {
                        result.success(mapOf("type" to "ready", "version" to 1))
                    }
                } catch (e: Exception) {
                    launch(Dispatchers.Main) {
                        result.error("E_START", e.message, null)
                    }
                }
            }
        }
        "fetch" -> {
            // TODO: Extract url and execute HTTP via PinVault.getClient()
            result.success(mapOf("status" to 200, "body" to "Success"))
        }
        "ws_connect" -> {
            val socketId = call.argument<String>("socketId") ?: return result.error("INVALID_ARGS", "socketId required", null)
            val url = call.argument<String>("url") ?: return result.error("INVALID_ARGS", "url required", null)
            
            setupWebSocket(socketId, url)
            result.success(null)
        }
        "send" -> {
            // ...
            result.success(null)
        }
        "close" -> {
            // ...
            result.success(null)
        }
        else -> {
            result.notImplemented()
        }
    }
  }

  private fun setupWebSocket(socketId: String, url: String) {
      val eventChannel = EventChannel(flutterPluginBinding.binaryMessenger, "pinvault_flutter/ws/\$socketId/events")
      
      var eventSink: EventChannel.EventSink? = null
      eventChannel.setStreamHandler(object : EventChannel.StreamHandler {
          override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
              eventSink = events
              
              val request = Request.Builder().url(url).build()
              // Ensure we use the client protected by PinVault!
              val client = PinVault.getClient()
              
              val ws = client.newWebSocket(request, object : WebSocketListener() {
                  override fun onMessage(webSocket: WebSocket, text: String) {
                      CoroutineScope(Dispatchers.Main).launch {
                          eventSink?.success(mapOf("type" to "message", "data" to text))
                      }
                  }
                  
                  override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                      CoroutineScope(Dispatchers.Main).launch {
                          eventSink?.success(mapOf("type" to "closed"))
                      }
                  }

                  override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                      CoroutineScope(Dispatchers.Main).launch {
                          eventSink?.success(mapOf("type" to "error", "error" to t.message))
                      }
                  }
              })
              activeSockets[socketId] = ws
          }

          override fun onCancel(arguments: Any?) {
              activeSockets[socketId]?.close(1000, "Cancelled")
              activeSockets.remove(socketId)
              eventSink = null
          }
      })
  }

  override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }
}
