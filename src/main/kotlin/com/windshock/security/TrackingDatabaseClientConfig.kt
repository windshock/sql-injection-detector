package com.windshock.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.context.annotation.Configuration
import org.springframework.data.r2dbc.core.DatabaseClient
import java.util.Collections

/**
 * Configuration to replace DatabaseClient with TrackingDatabaseClient in test environment
 * to enable bind() tracking.
 */

@Configuration
open class TrackingDatabaseClientConfig {
    companion object {
        data class BindTrace(val name: String, val value: Any?, val caller: StackTraceElement?)
        val globalBoundParameters = Collections.synchronizedList(mutableListOf<BindTrace>())
    }

    @Bean("r2dbcDatabaseClient")
    @Primary
    open fun r2dbcDatabaseClient(): DatabaseClient {
        val connectionFactory = io.r2dbc.h2.H2ConnectionFactory(
            io.r2dbc.h2.H2ConnectionConfiguration.builder()
                .inMemory("testdb")
                .username("sa")
                .build()
        )
        val delegate = org.springframework.data.r2dbc.core.DatabaseClient.create(connectionFactory)
        return TrackingDatabaseClient(delegate) { name, value, caller ->
            globalBoundParameters.add(BindTrace(name, value, caller))
            val callerInfo = caller?.let { "at ${it.className}.${it.methodName}:${it.lineNumber}" } ?: "(unknown caller)"
            println("[TRACK] DatabaseClient.bind() called: $name = $value ($callerInfo)")
        }
    }
} 