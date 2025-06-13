# SQL Injection Detector

A test framework for detecting SQL Injection vulnerabilities in Spring Data R2DBC repositories.

## Features

- Detects SQL Injection vulnerabilities in Spring Data R2DBC repositories
- Performs static analysis to identify vulnerability patterns
- Generates detailed reports when vulnerabilities are found

## Usage

1. Add dependency:
```kotlin
dependencies {
    testImplementation("com.windshock:sql-injection-detector:1.0.0")
}
```

2. Add annotation to your test class:
```kotlin
@SqlInjectionTest
class YourRepositoryTest {
    // test code
}
```

## Vulnerability Patterns

Currently detectable vulnerability patterns:
- Direct string concatenation (`+`, `$`)
- Template literal usage (`${param}`)
- Direct parameter insertion (`' + param`)

## Future Development Plans

1. **Dynamic Analysis Integration**
   - Integrate fuzzing tools like Jazzer for dynamic analysis
   - Implement focused fuzzing tests for SQL generation utilities (e.g., `Utils.toSql`)
   - Detect vulnerabilities at runtime

2. **SafeSqlUtils Development**
   - Separate SQL generation utilities into a safe version
   - Implement secure SQL generation patterns (parameter binding, PreparedStatement)
   - Create developer guidelines

3. **Test Coverage Expansion**
   - Detect more complex SQL Injection patterns
   - Support various database drivers
   - Add test cases from production environments

## Contributing

1. Create an issue
2. Create a branch
3. Commit changes
4. Create a Pull Request

## License

MIT License
