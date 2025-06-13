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

## SQL Injection 취약점을 감지하는 테스트 프레임워크입니다.

## 주요 기능

- Spring Data R2DBC Repository의 SQL Injection 취약점 감지
- 정적 분석을 통한 취약점 패턴 검사
- 취약점 발견 시 상세한 리포트 생성

## 사용 방법

1. 의존성 추가:
```kotlin
dependencies {
    testImplementation("com.windshock:sql-injection-detector:1.0.0")
}
```

2. 테스트 클래스에 어노테이션 추가:
```kotlin
@SqlInjectionTest
class YourRepositoryTest {
    // 테스트 코드
}
```

## 취약점 패턴

현재 감지 가능한 취약점 패턴:
- 직접적인 문자열 연결 (`+`, `$`)
- 템플릿 리터럴 사용 (`${param}`)
- 직접적인 파라미터 삽입 (`' + param`)

## 향후 개발이 필요한 사항

1. **동적 분석 도구 통합**
   - Jazzer와 같은 fuzzing 도구를 활용한 동적 분석 추가
   - SQL 생성 유틸리티(`Utils.toSql` 등)에 대한 집중적인 fuzzing 테스트
   - 실제 실행 시점의 취약점 발견

2. **SafeSqlUtils 개발**
   - SQL 생성 유틸리티를 안전한 버전으로 분리
   - 파라미터 바인딩, PreparedStatement 등 안전한 SQL 생성 패턴 적용
   - 개발자 가이드라인 작성

3. **테스트 커버리지 확장**
   - 더 복잡한 SQL Injection 패턴 감지
   - 다양한 데이터베이스 드라이버 지원
   - 실제 프로덕션 환경에서의 테스트 케이스 추가

## 기여 방법

1. 이슈 생성
2. 브랜치 생성
3. 변경사항 커밋
4. Pull Request 생성

## 라이선스

MIT License
