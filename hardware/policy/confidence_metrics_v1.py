"""One selected confidence recipe from fresh in-memory SV arrays and parts only.

compute_confidence(arrays, parts, recipe='mean_entry_maxposterior')
compute_confidence(arrays, parts, recipe='normalized_shannon_entry')  # score=1-H
compute_confidence(arrays, parts, recipe='entry_maxposterior_statistics')

The statistics recipe alone additionally returns mean_confidence/min_confidence/
q10_confidence, matching np.mean, min and np.quantile(.1, method='linear') over
ALL entry posteriors in part order. No min/quantile work is charged to other
recipes. select_mixture_component(weights, uniform_draw=...) is a pure selector;
caller persists assignments BEFORE NN, not after seeing any output/label.

Each array is float32 [1,V,T] or [1,V,1,T]. Each matching part supplies only
valid_frames and token_ids. Speech is flat[0].T[4:4+valid_frames]; blank=0,
collapse consecutive argmax IDs BEFORE removing blank, reset at every part.
Expected greedy IDs must replay exactly. Invalid/missing arrays raise; they are
not successful empty speech. Successful zero-entry input returns confidence=None
and always_escalate=True, which the caller must handle BEFORE numeric gating.

No IO, model/framework import, source bank, output lookup or memoization. Only the
selected recipe is calculated. Choose the frozen mixture component BEFORE this
call; caller measures all actual validation/array/confidence work inside service.
This module neither measures nor assumes zero online cost and performs no NN call.
Entry entropy uses only selected rows, preserving the full-speech cast's C/F
reduction order. A singleton entry from a multirow F-layout speech matrix uses
two identical scratch rows to prevent NumPy switching to the C pairwise fast
path; only its first entropy is counted. Validation/argmax still scan valid speech.
Caller retains measured full service and measured confidence cost separately;
an optimistic component diagnostic excluding confidence cost is not actual service.
"""
import math

import numpy as np

MEAN_RECIPE = 'mean_entry_maxposterior'
SHANNON_RECIPE = 'normalized_shannon_entry'
STATISTICS_RECIPE = 'entry_maxposterior_statistics'
RECIPES = (MEAN_RECIPE, SHANNON_RECIPE, STATISTICS_RECIPE)


def select_mixture_component(weights, *, uniform_draw):
    """Return one component index from explicit frozen weights and U in [0,1).

    No RNG, seed, IO, assignment storage, NN or input/outcome access is hidden
    here. Caller draws once per source in frozen manifest order, persists the
    assignment before NN and reuses it for timing repeats. Only that component's
    recipe is then computed. Weights are validated, NEVER fitted/renormalized.
    Exact cumulative-boundary draws go to the next positive-weight component.
    """
    if not isinstance(weights, (list, tuple)) or not weights:
        raise ValueError('nonempty explicit frozen weight sequence required')
    if any(type(w) not in (int, float) or not math.isfinite(w) or not 0 <= w <= 1 for w in weights):
        raise ValueError('finite nonnegative numeric weights required')
    if not math.isclose(math.fsum(weights), 1., rel_tol=0., abs_tol=1e-12):
        raise ValueError('frozen weights must sum to one; no normalization')
    if type(uniform_draw) not in (int, float) or not math.isfinite(uniform_draw) or not 0 <= uniform_draw < 1:
        raise ValueError('explicit uniform draw in [0,1) required')
    cumulative = 0.
    last_positive = None
    for index, weight in enumerate(weights):
        if weight > 0:
            last_positive = index
        cumulative += weight
        if uniform_draw < cumulative:
            return index
    # Assign only floating-point upper-tail residue, never a zero-weight branch.
    return last_positive


def _log_softmax(logits):
    # Keep NumPy's default order='K' cast, including its reduction layout.
    # Entropy prepares entry rows in the original speech cast's C/F order;
    # maxposterior keeps its original entry-only selection order.
    x = logits.astype(np.float64)
    z = x - x.max(axis=1, keepdims=True)
    return z - np.log(np.exp(z).sum(axis=1, keepdims=True))


def _entry_posteriors(logits, ids, entries):
    logp = _log_softmax(logits[entries])
    return np.exp(logp[np.arange(len(entries)), ids[entries]]).tolist()


def _entry_entropy_sum(logits, entries):
    # Match order='K' float64 casting of the full valid-speech view WITHOUT
    # computing logsoftmax/H for its blank/repeated, unselected frames. For a
    # 2D view with both dimensions >1, NumPy preserves the faster stride axis.
    # Single-valid-frame input is C/F contiguous and keeps its normal fast path.
    fortran = logits.shape[0] > 1 and abs(logits.strides[0]) < abs(logits.strides[1])
    selected = np.array(logits[entries], dtype=np.float64, order='F' if fortran else 'C')
    if fortran and len(entries) == 1:
        # shape(1,V) is BOTH C/F contiguous even with order='F'; a duplicate of
        # this same entry keeps the original strided-vocabulary reduction path.
        scratch = np.empty((2, logits.shape[1]), dtype=np.float64, order='F')
        scratch[:] = selected
        selected = scratch
    logp = _log_softmax(selected)
    entropy = -np.sum(np.exp(logp) * logp, axis=1) / math.log(logits.shape[1])
    if not (np.isfinite(entropy).all() and (entropy >= -1e-12).all() and (entropy <= 1 + 1e-12).all()):
        raise ValueError('normalized Shannon entropy outside roundoff bounds')
    # Same per-frame roundoff clipping, part sum and cross-part weighting as the
    # verified scalar derivation. No mean/max-posterior recipe is computed here.
    return float(np.clip(entropy, 0., 1.)[:len(entries)].sum())


def _entry_statistics(values):
    # Keep the verified cached-confidence summaries and quantile convention.
    # Called ONLY when the RF feature-statistics recipe was explicitly selected.
    if not values:
        return dict(mean_confidence=None, min_confidence=None, q10_confidence=None)
    return dict(mean_confidence=float(np.mean(values)), min_confidence=min(values),
        q10_confidence=float(np.quantile(values, .1, method='linear')))


def compute_confidence(arrays, parts, *, recipe):
    """Return scalar confidence, explicit empty action and scalar part counts.

    Mean = np.mean(concatenated entry posterior floats), NOT mean(part means).
    Shannon score = 1 - fsum(part entry-entropy sums)/total entry count.
    Statistics adds min and linear q10 over that same concatenated posterior list.
    No transcript/label/reference or timing/cost argument is accepted or read.
    """
    if recipe not in RECIPES:
        raise ValueError('one supported recipe must be selected explicitly')
    if not isinstance(arrays, (list, tuple)) or not isinstance(parts, (list, tuple)):
        raise TypeError('fresh array/part sequences required')
    if not arrays or len(arrays) != len(parts):
        raise ValueError('nonempty one-to-one fresh array/part sequence required')
    vocabulary = None
    entry_count = 0
    valid_count = 0
    part_counts = []
    # Populate only the selected accumulator; no unused recipe/aggregation work.
    values = []
    for array, part in zip(arrays, parts):
        if not isinstance(array, np.ndarray) or array.dtype != np.dtype('<f4'):
            raise TypeError('actual float32 SV ndarray required; no implicit tensor conversion')
        if (array.ndim not in (3, 4) or array.shape[0] != 1
                or any(x <= 0 for x in array.shape)
                or (array.ndim == 4 and array.shape[2] != 1)
                or array.shape[1] <= 1):
            raise ValueError('SV geometry must be [1,V,T] or [1,V,1,T], V>1')
        if not isinstance(part, dict):
            raise TypeError('fresh part metadata required')
        valid, expected = part['valid_frames'], part['token_ids']
        if type(valid) is not int or not 0 <= valid <= array.shape[-1] - 4:
            raise ValueError('invalid speech frame extent')
        if not isinstance(expected, (list, tuple)) or any(type(t) is not int or not 0 < t < array.shape[1] for t in expected):
            raise ValueError('greedy nonblank integer token IDs required')
        if vocabulary is not None and vocabulary != array.shape[1]:
            raise ValueError('one frozen vocabulary required across parts')
        vocabulary = array.shape[1]
        flat = array[:, :, 0, :] if array.ndim == 4 else array
        logits = flat[0].T[4:4 + valid]
        if logits.shape != (valid, vocabulary) or not np.isfinite(logits).all():
            raise ValueError('finite valid-speech logits required')
        ids = logits.argmax(axis=1)
        changed = np.ones(valid, dtype=bool)
        if valid:
            changed[1:] = ids[1:] != ids[:-1]
        entries = np.flatnonzero((ids != 0) & changed)
        if ids[entries].tolist() != list(expected):
            raise ValueError('fresh greedy token replay mismatch')
        count = len(entries)
        entry_count += count
        valid_count += valid
        part_counts.append(dict(valid_frames=valid, entry_count=count, vocabulary_size=vocabulary))
        if count:
            if recipe in (MEAN_RECIPE, STATISTICS_RECIPE):
                values.extend(_entry_posteriors(logits, ids, entries))
            else:
                values.append(_entry_entropy_sum(logits, entries))
    statistics = _entry_statistics(values) if recipe == STATISTICS_RECIPE else None
    if statistics is not None:
        confidence = statistics['mean_confidence']
    elif not entry_count:
        confidence = None
    elif recipe == MEAN_RECIPE:
        confidence = float(np.mean(values))
    else:
        confidence = 1. - math.fsum(values) / entry_count
    if confidence is not None and not (math.isfinite(confidence) and 0 <= confidence <= 1):
        raise ValueError('invalid selected confidence scalar')
    result = dict(recipe=recipe, confidence=confidence, entry_count=entry_count,
        valid_frames=valid_count, part_counts=part_counts, always_escalate=entry_count == 0)
    if statistics is not None:
        result.update(statistics)
    return result
