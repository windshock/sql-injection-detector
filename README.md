# SQL Injection Detector

🔧 **Shift Left Security Testing for Kotlin Applications**

> "Bugs are cheap when caught young."

## Why This Project?

In the early 2000s, Larry Smith formalized "Shift Left Testing," arguing that quality assurance shouldn't be a late-stage blocker but part of development from the start. This principle has become even more crucial in security testing.

While traditional security testing often happens late in the development cycle, this project brings SQL injection detection directly into your build process. By integrating security testing with your regular unit tests, we catch vulnerabilities early and make them part of your development workflow.

### The Challenge

Security teams often struggle to integrate with development tools, while developers find traditional security tools (AST/SAST/RAST) too heavy, noisy, and complex. This project bridges that gap by:

1. Running security checks as part of your build-time tests
2. Using familiar testing frameworks (JUnit)
3. Providing clear, actionable results
4. Requiring no external security tools or complex setup

## Features

- Static analysis of Kotlin source code using ANTLR
- Detection of SQL injection vulnerabilities in repository methods
- Support for Spring Data R2DBC repositories
- Detailed vulnerability reports with risk levels
- Test coverage for security analysis

## Overview

SQL Injection Detector is a static analysis tool for Kotlin projects, designed to detect SQL injection vulnerabilities in Spring Data R2DBC repositories. It integrates with your build and test process, enabling early detection of security issues.

## Prerequisites

- JDK 17 or higher
- Gradle 8.0+ or Maven
- Kotlin 1.8.0+

## Publishing to Local Maven

This library is not distributed via Maven Central.  
To use it in your projects, you must first publish it to your local Maven repository:

```sh
./gradlew publishToMavenLocal
```

## Adding the Dependency

After publishing, add the dependency to your project:

### Gradle (Kotlin DSL)
```kotlin
repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    testImplementation("com.windshock.security:sql-injection-detector:1.0.0")
}
```

### Maven
```xml
<repositories>
    <repository>
        <id>local</id>
        <url>file://${user.home}/.m2/repository</url>
    </repository>
    <repository>
        <id>central</id>
        <url>https://repo.maven.apache.org/maven2</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.windshock.security</groupId>
    <artifactId>sql-injection-detector</artifactId>
    <version>1.0.0</version>
    <scope>test</scope>
</dependency>
```

## Usage Example

Create a test class in your Spring Data R2DBC project:

```kotlin
import com.windshock.security.SqlInjectionTestRunner
import com.windshock.security.TrackingDatabaseClientConfig
import org.junit.jupiter.api.Test
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest
import org.springframework.context.annotation.Import
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext

@DataR2dbcTest
@Import(TrackingDatabaseClientConfig::class)
class RepositorySqlInjectionSpringTest {
    @Autowired
    lateinit var applicationContext: ApplicationContext

    @Test
    fun scanAllRepositories() {
        SqlInjectionTestRunner.scanRepositories("com.yourcompany.yourpackage.repository", applicationContext)
    }
}
```

Run this test to scan all repositories in the specified package for SQL injection vulnerabilities. Results will be reported in the test output.

## Project Structure (Example)

```
src/
  main/
    kotlin/
      com/
        windshock/
          security/
            SqlInjectionTestRunner.kt
            TrackingDatabaseClientConfig.kt
            ...
```

## License

[Specify your license here]

```kotlin
@SpringBootTest
class YourRepositoryTest {
    @Autowired
    private lateinit var sqlInjectionAnalyzer: SqlInjectionAstAnalyzer
    
    @Test
    fun testSqlInjection() {
        val result = sqlInjectionAnalyzer.analyzeRepositories()
        assert(result.vulnerabilities.isEmpty()) {
            "SQL injection vulnerabilities detected: ${result.vulnerabilities}"
        }
    }
}
```

## How It Works

1. **AST Analysis**: Uses ANTLR to parse Kotlin source code and generate an Abstract Syntax Tree (AST)
2. **Repository Scanning**: Identifies repository interfaces and their methods
3. **Vulnerability Detection**: Analyzes SQL queries for potential injection points
4. **Report Generation**: Creates detailed reports of detected vulnerabilities

## Core Logic & Implementation Details

### 1. Automatic Repository Method Execution
- The `AllRepositoriesBindingTest` class uses reflection to automatically execute all Repository methods
- No need to write individual test cases—new Repository classes or methods are automatically included in validation
- Provides comprehensive coverage without manual test maintenance

### 2. DatabaseClient Wrapping for Binding Tracking
- At build-time test execution, the DatabaseClient is wrapped with `TrackingDatabaseClient`
- Records parameter name, value, and call location for each `.bind()` call during query execution
- Seamlessly integrates with normal query flow—just running the test triggers full binding tracking

### 3. Precise Analysis of Unbound Parameters
- Compares declared parameters against actually bound variables during execution
- Extracts and analyzes only unbound parameters
- Normalizes parameter names (lowercase, underscore removal) for precise SQL parameter matching

### 4. In-Test Kotlin AST Analysis
- Performs Kotlin AST analysis directly within test code
- Uses official Kotlin ANTLR grammar embedded in the project
- No external tools required for analysis

### 5. Accurate Vulnerability Reporting
- Reports SQL injection vulnerabilities only when unbound parameters are directly inserted into query strings via:
  - String concatenation (+)
  - String templates ($)
  - `.toString()`, `.append()`, etc.
- Automatically ignores false positives from:
  - Control flow
  - Conditional logic
  - Query composition
  - Other non-injection cases

## ANTLR Grammar & Customization

The project uses ANTLR for parsing Kotlin source code. The ANTLR parser/lexer files are generated in the `src/main/java/com/windshock/security/` directory during the build process. Grammar files are not provided separately as they are included in the build dependencies.

To regenerate the parser/lexer files, run:
```bash
./gradlew generateGrammarSource
```

## Module Structure

```
sql-injection-detector/
├── src/
│   ├── main/
│   │   ├── kotlin/
│   │   │   └── com/windshock/
│   │   │       ├── repository/     # Repository interfaces
│   │   │       └── security/       # Security analysis tools
│   │   └── java/
│   │       └── com/windshock/security/
│   │           ├── KotlinLexer.java    # Generated ANTLR lexer
│   │           └── KotlinParser.java   # Generated ANTLR parser
│   └── test/
│       └── kotlin/
│           └── com/windshock/security/   # Test cases
└── build.gradle.kts
```

## Future Development Plans

1. **Dynamic Analysis Integration**
   - Integrate fuzzing tools like Jazzer for dynamic analysis
   - Implement focused fuzzing tests for SQL generation utilities (e.g., `Utils.toSql`)
   - Detect vulnerabilities at runtime

2. **Test Coverage Expansion**
   - Detect more complex SQL Injection patterns
   - Support various database drivers
   - Add test cases from production environments

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [ANTLR](https://www.antlr.org/) - Parser generator
- [Spring Data R2DBC](https://spring.io/projects/spring-data-r2dbc) - Reactive database access
- [Kotlin](https://kotlinlang.org/) - Programming language
- [Kotlin Grammar](https://github.com/Kotlin/kotlin-spec/tree/release/grammar/src/main/antlr) - Kotlin language grammar specification used for AST analysis