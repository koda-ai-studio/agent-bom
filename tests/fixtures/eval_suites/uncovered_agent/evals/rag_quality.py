"""Synthetic ragas quality eval: read by the scanner, never executed."""

from ragas import evaluate
from ragas.metrics import answer_relevancy, faithfulness

samples = []

result = evaluate(samples, metrics=[faithfulness, answer_relevancy])
