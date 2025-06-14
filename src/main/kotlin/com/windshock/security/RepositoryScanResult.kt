package com.windshock.security

data class RepositoryScanResult(
    val repositoryName: String,
    val totalMethods: Int,
    val vulnerabilities: List<VulnerabilityReport>
) {
    fun hasVulnerabilities(): Boolean = vulnerabilities.any { it.riskLevel == RiskLevel.CRITICAL }
    fun getVulnerabilityCount(): Int = vulnerabilities.count { it.riskLevel == RiskLevel.CRITICAL }
} 