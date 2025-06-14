package com.windshock.security

import org.springframework.data.r2dbc.core.DatabaseClient

/**
 * DatabaseClient의 bind() 호출을 추적하기 위한 래퍼 클래스
 */
class TrackingDatabaseClient(
    private val delegate: DatabaseClient,
    private val onBind: (String, Any?, StackTraceElement?) -> Unit
) : DatabaseClient by delegate {
    override fun execute(sql: String): DatabaseClient.GenericExecuteSpec {
        val spec = delegate.execute(sql)
        return TrackingGenericExecuteSpec(spec, onBind)
    }
}

class TrackingGenericExecuteSpec(
    private val delegate: DatabaseClient.GenericExecuteSpec,
    private val onBind: (String, Any?, StackTraceElement?) -> Unit
) : DatabaseClient.GenericExecuteSpec by delegate {
    override fun bind(name: String, value: Any): DatabaseClient.GenericExecuteSpec {
        val caller = Throwable().stackTrace.firstOrNull { it.className.startsWith("com.skplanet") && !it.className.contains("Tracking") }
        onBind(name, value, caller)
        return TrackingGenericExecuteSpec(delegate.bind(name, value), onBind)
    }
    override fun bind(index: Int, value: Any): DatabaseClient.GenericExecuteSpec {
        val caller = Throwable().stackTrace.firstOrNull { it.className.startsWith("com.skplanet") && !it.className.contains("Tracking") }
        onBind(index.toString(), value, caller)
        return TrackingGenericExecuteSpec(delegate.bind(index, value), onBind)
    }
} 