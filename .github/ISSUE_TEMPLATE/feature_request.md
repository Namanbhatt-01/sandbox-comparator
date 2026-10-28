name: Feature Request
description: Suggest an idea or new capability for Sandbox Comparator
title: "[FEATURE] "
labels: ["enhancement"]
body:
  - type: markdown
    attributes:
      value: |
        Thank you for suggesting a feature! Please ensure the proposed feature adheres to our core principles: evidence-awareness, offline-first execution, and zero outbound telemetry.
  - type: textarea
    id: problem
    attributes:
      label: Problem Statement
      description: Is your feature request related to a problem or gap in sandbox comparison?
      placeholder: "A clear and concise description of what the problem is..."
    validations:
      required: true
  - type: textarea
    id: solution
    attributes:
      label: Proposed Solution
      description: A clear and concise description of what you want to happen.
    validations:
      required: true
  - type: textarea
    id: evidence
    attributes:
      label: Evidence Provenance Considerations
      description: How should this feature link findings back to source RFC 6901 pointers?
    validations:
      required: false
