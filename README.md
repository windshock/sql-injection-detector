# SQL Injection Detector

A static analysis tool that detects SQL injection vulnerabilities in Kotlin repositories using ANTLR-based AST analysis.

## Features

- Static analysis of Kotlin source code using ANTLR
- Detection of SQL injection vulnerabilities in repository methods
- Support for Spring Data R2DBC repositories
- Detailed vulnerability reports with risk levels
- Test coverage for security analysis

## Prerequisites

- JDK 17 or higher
- Gradle 8.0 or higher
- Kotlin 1.8.0 or higher

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/sql-injection-detector.git
cd sql-injection-detector
```

2. Build the project:
```bash
./gradlew build
```

## Usage

1. Add the following dependencies to your project's `build.gradle.kts`:

```kotlin
dependencies {
    implementation(project(":sql-injection-detector"))
    testImplementation(project(":sql-injection-detector"))
}
```

2. Create a test class to scan your repositories:

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
