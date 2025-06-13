package com.example.repository

import org.springframework.stereotype.Repository
import org.springframework.data.r2dbc.core.DatabaseClient
import reactor.core.publisher.Mono

@Repository
open class SampleVulnerableRepository(val client: DatabaseClient) {
    // Vulnerable: Directly inserting userId into query string (no binding used)
    fun findUserByIdVulnerable(userId: String): Mono<Map<String, Any>> {
        val query = """
            SELECT * FROM users WHERE user_id = '$userId'
        """.trimIndent()
        return client.execute(query)
            .fetch()
            .one()
    }

    // Safe: Using parameter binding
    fun findUserByIdSafe(userId: String): Mono<Map<String, Any>> {
        val query = "SELECT * FROM users WHERE user_id = :userId"
        return client.execute(query)
            .bind("userId", userId)
            .fetch()
            .one()
    }
}
