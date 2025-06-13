package com.windshock.repository

import org.springframework.stereotype.Repository
import org.springframework.data.r2dbc.core.DatabaseClient
import org.springframework.data.relational.core.query.Criteria
import org.springframework.data.domain.Pageable
import org.springframework.data.domain.Sort
import org.springframework.data.relational.core.query.CriteriaDefinition
import reactor.core.publisher.Mono
import reactor.core.publisher.Flux

data class User(
    val id: Long,
    val mediaCompanyId: Long,
    val mediaCompanyName: String,
    val pwd: String,
    val email: String,
    val name: String,
    val phone: String,
    val acl: String,
    val state: String,
    val lastLoginDate: String,
    val registerDate: String,
    val pwdModifyDate: String
)

data class CoupangStat(
    val id: Long,
    val subId: String,
    val mediaId: String,
    val date: String,
    val clicks: Int,
    val orders: Int,
    val sales: Double
)

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

    fun findByEmail2(email: String): Mono<User> {
        return client.execute("SELECT\n" +
                "        id, media_company_id, " +
                "        (SELECT title FROM media_company WHERE id = media_company_id) as media_company_name," +
                "        pwd, email, name, phone, acl, state," +
                "        last_login_date, register_date, pwd_modify_date\n" +
                "   FROM user WHERE " + Criteria.where("email").`is`(email).toString())
                .`as`(User::class.java)
                .fetch()
                .one()
    }

    // Vulnerable: Complex SQL injection pattern with nested queries and string formatting
    fun findCoupangDailyStatVulnerable(
        startDate: String,
        endDate: String,
        mediaCompanyId: String?,
        mediaIds: String?,
        subId: String?
    ): Flux<CoupangStat> {
        var baseCond = " and sub_id in (%s)"
        var mediaCond = "SELECT sub_id FROM inventory WHERE media_id in (%s) %s"
        var subIdCond = " and sub_id like '%%%s%%'"
        var mediaCompanyCond = "SELECT id FROM media WHERE media_company_id = '%s' %s"

        // For non-admin users
        if(mediaCompanyId != null) {
            mediaCompanyCond = mediaCompanyCond.format(mediaCompanyId,
                    if(mediaIds != null) " and id in ('%s')".format(mediaIds.replace(",", "','"))
                    else " ")

            mediaCond = mediaCond.format(mediaCompanyCond, if(subId != null) subIdCond.format(subId) else " ")
            baseCond = baseCond.format(mediaCond)
        } else {
            if(mediaIds != null) {
                baseCond = baseCond.format(mediaCond.format("'"+mediaIds.replace(",", "','")+"'",
                        if(subId != null) "and sub_id like '%%%s%%'".format(subId)
                        else ""))
            } else {
                baseCond = if(subId != null) " and sub_id like '%%%s%%'".format(subId) else " "
            }
        }

        val query = """
            SELECT 
                id, sub_id, media_id, date, clicks, orders, sales
            FROM coupang_daily_stat
            WHERE date BETWEEN :startDate AND :endDate
            $baseCond
        """.trimIndent()

        return client.execute(query)
                .bind("startDate", startDate)
                .bind("endDate", endDate)
                .`as`(CoupangStat::class.java)
                .fetch()
                .all()
    }

    // Safe: Using parameter binding
    fun findUserByIdSafe(userId: String): Mono<Map<String, Any>> {
        val query = "SELECT * FROM users WHERE user_id = :userId"
        return client.execute(query)
            .bind("userId", userId)
            .fetch()
            .one()
    }

    // Vulnerable: Using Utils.toSql with Pageable
    fun findUsersWithSortVulnerable(pageable: Pageable): Flux<User> {
        val query = """
            SELECT 
                id, media_company_id, 
                (SELECT title FROM media_company WHERE id = media_company_id) as media_company_name,
                pwd, email, name, phone, acl, state,
                last_login_date, register_date, pwd_modify_date
            FROM user
            ${Utils.toSql(pageable)}
        """.trimIndent()

        return client.execute(query)
            .`as`(User::class.java)
            .fetch()
            .all()
    }

    // Vulnerable: Using Utils.toSql with CriteriaDefinition
    fun findUsersWithCriteriaVulnerable(criteria: CriteriaDefinition): Flux<User> {
        val query = """
            SELECT 
                id, media_company_id, 
                (SELECT title FROM media_company WHERE id = media_company_id) as media_company_name,
                pwd, email, name, phone, acl, state,
                last_login_date, register_date, pwd_modify_date
            FROM user
            ${Utils.toSql(criteria)}
        """.trimIndent()

        return client.execute(query)
            .`as`(User::class.java)
            .fetch()
            .all()
    }
}

// Vulnerable: Utils class with unsafe SQL generation
object Utils {
    fun toSql(page: Pageable): String {
        val sql = StringBuilder()
        
        if (!page.sort.isEmpty) {
            sql.append(" ORDER BY ")
            val sortString = page.sort.toString()
            val cleanedSort = sortString.replace(Regex("\\:"), "")
            sql.append(cleanedSort)
        }

        if (page.isPaged) {
            sql.append(" LIMIT :offset, :pageSize")
        }

        return sql.toString()
    }

    fun toSql(definition: CriteriaDefinition): String {
        val sql = StringBuilder()
        
        if (!definition.isEmpty) {
            sql.append(" WHERE ")
            sql.append(definition.toString())
        }

        return sql.toString()
    }
}
