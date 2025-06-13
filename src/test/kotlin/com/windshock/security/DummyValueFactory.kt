package com.windshock.security

import kotlin.reflect.KType
import kotlin.reflect.full.createInstance
import kotlin.reflect.full.isSubclassOf
import kotlin.reflect.jvm.jvmErasure
import java.time.LocalDateTime
import org.springframework.context.ApplicationContext

object DummyValueFactory {
    fun createDummyValue(type: KType, applicationContext: ApplicationContext? = null): Any? = when {
        type.isMarkedNullable -> null
        type.jvmErasure.qualifiedName == "org.springframework.data.r2dbc.core.DatabaseClient" && applicationContext != null ->
            applicationContext.getBean(Class.forName("org.springframework.data.r2dbc.core.DatabaseClient"))
        type.jvmErasure == String::class -> "dummy"
        type.jvmErasure == Int::class -> 0
        type.jvmErasure == Long::class -> 0L
        type.jvmErasure == Boolean::class -> false
        type.jvmErasure == Double::class -> 0.0
        type.jvmErasure == Float::class -> 0.0f
        type.jvmErasure.java.isEnum -> type.jvmErasure.java.enumConstants.firstOrNull()
        type.jvmErasure.isSubclassOf(List::class) -> {
            val elementType = type.arguments.getOrNull(0)?.type
            if (elementType != null) listOf(createDummyValue(elementType)) else listOf("dummy")
        }
        type.jvmErasure.isSubclassOf(Map::class) -> {
            val keyType = type.arguments.getOrNull(0)?.type
            val valueType = type.arguments.getOrNull(1)?.type
            if (keyType != null && valueType != null)
                mapOf(createDummyValue(keyType) to createDummyValue(valueType))
            else mapOf("dummy" to "dummy")
        }
        type.jvmErasure.qualifiedName == "java.util.Optional" -> java.util.Optional.of("dummy")
        type.jvmErasure.qualifiedName == "org.springframework.data.domain.Pageable" -> org.springframework.data.domain.PageRequest.of(0, 1)
        type.jvmErasure.qualifiedName == "org.springframework.data.domain.Sort" -> org.springframework.data.domain.Sort.unsorted()
        type.jvmErasure.qualifiedName == "java.time.LocalDate" -> java.time.LocalDate.now()
        type.jvmErasure.qualifiedName == "java.time.LocalDateTime" -> java.time.LocalDateTime.now()
        type.jvmErasure.qualifiedName == "java.math.BigDecimal" -> java.math.BigDecimal.ZERO
        type.jvmErasure.constructors.any { it.parameters.isEmpty() } -> type.jvmErasure.createInstance()
        type.jvmErasure.constructors.isNotEmpty() -> {
            val ctor = type.jvmErasure.constructors.first()
            val args = ctor.parameters.map { p ->
                if (p.type.isMarkedNullable) null else createDummyValue(p.type)
            }.toTypedArray<Any?>()
            ctor.call(*args)
        }
        else -> "dummy"
    }
}
