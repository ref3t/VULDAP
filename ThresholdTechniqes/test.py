import nltk

def segment_text_into_sentences(text, max_tokens):
    sentences = nltk.sent_tokenize(text)
    segments = []
    current_segment = []

    for sentence in sentences:
        # Tokenize the sentence
        tokens = nltk.word_tokenize(sentence)
        if len(current_segment) + len(tokens) > max_tokens:
            # If adding the next sentence exceeds the max_tokens limit,
            # add the current_segment to segments and start a new segment
            segments.append(' '.join(current_segment))
            current_segment = []

        current_segment.extend(tokens)

    # Add the last segment if it's non-empty
    if current_segment:
        segments.append(' '.join(current_segment))

    return segments

# Example usage:
text = "This is a very long text that needs to be segmented. It contains many sentences. Each sentence is treated as a separate unit."
segments = segment_text_into_sentences(text, 338)
print(segments)
