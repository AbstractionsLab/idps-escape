# IDPS-ESCAPE documentation

This directory contains all documentation for the IDPS-ESCAPE project, organized into distinct categories to support different audiences and purposes.

## Documentation structure

### `manual/` - User and developer manuals

**Audience**: End users, system administrators, and developers

**Purpose**: Practical, task-oriented documentation explaining **HOW** to use, configure, and operate the system.

**Contents**:
- `getting-started-stack.md` - Quick start for the full IDPS-ESCAPE stack
- `adbox_docs/` - ADBox v1 (legacy) user guides
- `radar_docs/` - RADAR setup, scenarios, and playbooks
- `sonar_docs/` - SONAR installation, configuration, and usage
- `_figures/` - Images and diagrams for manual documentation

**Characteristics**:
- Narrative, tutorial-style writing
- Step-by-step procedures
- Complete configuration examples
- Frequently updated, living documentation
- Code examples and CLI references

### `specs/` - Requirements and specifications (Doorstop)

**Audience**: System architects, requirements engineers, QA teams, auditors

**Purpose**: Formal, traceable requirements and design decisions defining **WHAT** and **WHY**.

**Contents**:
- `mrs/` - Market Requirements Specifications (root)
- `srs/` - Software Requirements Specifications (user stories)
- `harc/` - High-Level Architecture Requirements
- `larc/` - Low-Level Architecture Requirements
- `swd/` - Software Design Specifications
- `tst/` - Test Case Specifications
- `trp/` - Test Execution Reports
- `c5publish.py` - Custom Doorstop publisher
- `publish.sh` - Publishing script

**Characteristics**:
- Formal, structured format (Doorstop YAML frontmatter)
- Focus on acceptance criteria and rationale
- Primarily diagrams, decisions, constraints
- Upward traceability links (child → parent)
- Version-controlled with reviews/approval metadata

### `traceability/` - Published requirements traceability

**Audience**: Stakeholders, auditors, project managers

**Purpose**: Generated HTML documentation showing full requirements traceability matrix.

**Contents**:
- `index.html` - Traceability matrix home page
- `MRS.html`, `SRS.html`, `HARC.html`, etc. - Published requirement documents
- `traceability.csv` - Machine-readable traceability export
- `template/` - HTML templates for publishing
- `assets/` - Supporting files for published HTML

**Generation**: Run `cd docs/specs && ./publish.sh` to regenerate from Doorstop sources.

---

## Maintaining balance: specs vs. manual

The project uses a clear separation of concerns to avoid content duplication and minimize maintenance burden:

### Separation of concerns

| Aspect | `specs/` (Doorstop) | `manual/` |
|--------|---------------------|-----------|
| **Focus** | WHAT and WHY | HOW |
| **Content** | Requirements, acceptance criteria, design rationale | Setup guides, usage tutorials, configuration references |
| **Audience** | Architects, QA, auditors | Users, operators, developers |
| **Format** | Formal Doorstop documents | Narrative tutorials |
| **Stability** | Versioned, reviewed, formally approved | Living documentation, frequently updated |

### Content ownership matrix

| Content type | Owner | Example |
|-------------|-------|---------|
| User stories | Specs (SRS) | "As a security analyst, I want..." |
| Acceptance criteria | Specs (SRS) | "System shall validate YAML..." |
| Design rationale | Specs (HARC/LARC) | "Selected MVAD due to..." |
| Architecture diagrams | Specs (HARC/LARC) | Component relationship diagrams |
| CLI syntax | Manual | `poetry run sonar train --scenario...` |
| Configuration options | Manual | Field-by-field YAML reference |
| Installation steps | Manual | Numbered procedures |
| Troubleshooting | Manual | Error messages and solutions |
| Code examples | Manual | Complete working examples |
| API documentation | Manual | Function signatures, parameters |

### Reference, don't duplicate

**In specs**: State the requirement concisely

```markdown
# SRS-046: SONAR scenario execution

The system shall execute anomaly detection workflows defined in YAML scenario files.

### Rationale
Enable repeatable, version-controlled detection strategies.

### Acceptance criteria
- System loads and validates YAML scenario files
- Executes training/detection as specified
- See: docs/manual/sonar_docs/scenario-guide.md
```

**In manual**: Explain how to use it in detail

```markdown
# SONAR scenario guide

> **Requirements**: Implements [SRS-046](../../specs/srs/SRS-046.md)

Complete guide to creating and running YAML scenarios...
[detailed examples, field descriptions, troubleshooting]
```

### Cross-referencing guidelines

**Include in specs**:
```markdown
### Acceptance criteria
- System implements MVAD detection pipeline
- See implementation guide: docs/manual/sonar_docs/architecture.md
- Test case: TST-023
```

**Include in manual**:
```markdown
## Design principles

These principles implement requirements defined in:
- [HARC-012](../../specs/harc/HARC-012.md) - Modularity requirement
- [SRS-046](../../specs/srs/SRS-046.md) - Scenario execution
```

### Architecture diagrams

**Specs own architecture diagrams**:
- Store authoritative architecture diagrams in `specs/harc/assets/` and `specs/larc/assets/`
- Explain design rationale and constraints
- Link to related requirements

**Manual uses them**:
- Reference diagrams from specs with relative links: `![Diagram](../../specs/harc/assets/diagram.png)`
- Add workflow diagrams and user-oriented visuals in `manual/_figures/`
- Focus on operational understanding

### Update workflow

**When implementing a new feature**:
1. ✅ Update specs first (ensures requirement is traced)
2. ✅ Implement code
3. ✅ Update manual with usage instructions
4. ✅ Link from specs to manual section
5. ✅ Create test case (TST) linked to requirement (SRS)

**When updating existing functionality**:
1. ✅ Check if requirement changed (update SRS if needed)
2. ✅ Update implementation
3. ✅ Update manual documentation
4. ✅ Verify specs still reference correct manual sections

### Practical guidelines

#### 1. Single source of truth

- **Requirements**: Defined once in specs (SRS)
- **Design decisions**: Defined once in specs (HARC/LARC)
- **Usage instructions**: Defined once in manual
- **Configuration reference**: Defined once in manual

#### 2. Link liberally

Use relative links to connect specs ↔ manual:
- From specs: `See: docs/manual/sonar_docs/setup-guide.md`
- From manual: `Implements [SRS-046](../../specs/srs/SRS-046.md)`

#### 3. Avoid implementation details in specs

**❌ Wrong (in SRS)**:
```markdown
System shall use pandas.DataFrame.rolling() with window=200
```

**✅ Correct (in SRS)**:
```markdown
System shall apply sliding window aggregation to time-series data.
See: docs/manual/sonar_docs/architecture.md#sliding-window-implementation
```

#### 4. Avoid requirements in manual

**❌ Wrong (in manual)**:
```markdown
The system must validate YAML files before execution.
```

**✅ Correct (in manual)**:
```markdown
SONAR validates YAML scenario files before execution ([SRS-046](../../specs/srs/SRS-046.md)).
Here's how to fix common validation errors...
```

---

## Documentation standards

### File naming

- **Use lowercase**: Documentation file names should be lowercase with hyphens
- ✅ Correct: `debug-mode.md`, `setup-guide.md`, `uml-diagrams.md`
- ❌ Incorrect: `DEBUG-MODE.md`, `Setup-Guide.md`, `UML-DIAGRAMS.md`
- **Exception**: `README.md` should remain uppercase (standard convention)

### Section headings

- **Use sentence case**: Only capitalize the first word and proper nouns in headings
- ✅ Correct: `## Data flow`, `## Getting started`, `### Error handling`
- ❌ Incorrect: `## Data Flow`, `## Getting Started` (title case)

### Doorstop link direction

- **⚠️ CRITICAL**: Doorstop links are **upward-only** (child → parent)
- ✅ Correct: `SRS-001` links to `MRS-002` (child links up to parent)
- ❌ Wrong: `MRS-002` links to `SRS-001` (parent cannot link down to child)
- Downward links cause `RecursionError` during publishing

---

## Automation opportunities

### Link validation

Consider creating `docs/validate_cross_refs.py` to check cross-references:

```python
"""Validate cross-references between specs and manual."""
import re
from pathlib import Path

def find_broken_links():
    """Check that all specs→manual references are valid."""
    specs = Path("docs/specs").rglob("*.md")
    for spec in specs:
        refs = re.findall(r'docs/manual/[^\s)]+', spec.read_text())
        for ref in refs:
            if not Path(ref).exists():
                print(f"{spec}: Broken link to {ref}")

if __name__ == "__main__":
    find_broken_links()
```

### Enhanced publishing

The `specs/c5publish.py` custom publisher can be extended to automatically include manual references in published specs by enhancing the template to detect `manual_ref` attributes.

---

## Quick reference

| Task | Command/Location |
|------|------------------|
| View published specs | Open `docs/traceability/index.html` in browser |
| Regenerate published specs | `cd docs/specs && ./publish.sh` |
| Validate Doorstop structure | `poetry run doorstop` |
| Add new requirement | `poetry run doorstop add srs` |
| Link requirement | `poetry run doorstop link CHILD_UID PARENT_UID` |
| Browse manual | Start at `docs/manual/README.md` |
| AI context guides | See `docs/dev/` directory |

---

## Contributing to documentation

### Adding new manual documentation

1. Determine the appropriate subsystem: `adbox_docs/`, `radar_docs/`, or `sonar_docs/`
2. Create file with lowercase-hyphenated name: `my-feature-guide.md`
3. Use sentence case for headings
4. Link to related specs where applicable
5. Update subsystem README.md to reference new guide

### Adding new specifications

1. Create requirement in appropriate document: `poetry run doorstop add srs`
2. Edit the generated markdown file with requirement details
3. Add upward links to parent requirements: `poetry run doorstop link SRS-XXX MRS-YYY`
4. Include reference to manual documentation in acceptance criteria
5. Validate: `poetry run doorstop`
6. Publish: `cd docs/specs && ./publish.sh`

### Updating existing documentation

1. Check if change affects requirements (update specs if needed)
2. Update implementation
3. Update manual documentation
4. Verify cross-references are still valid
5. For specs changes: republish traceability

---

## Questions and support

- **Component-specific guides**: See relevant file in `dev/`
- **User guides**: See `manual/README.md`
- **Requirements traceability**: See `traceability/index.html`
