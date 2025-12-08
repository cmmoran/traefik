package dynamic

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (r *RouterObservabilityConfig) DeepCopyInto(out *RouterObservabilityConfig) {
	*out = *r
	if r.AccessLogs != nil {
		in, out := &r.AccessLogs, &out.AccessLogs
		*out = new(bool)
		**out = **in
	}
	if r.Metrics != nil {
		in, out := &r.Metrics, &out.Metrics
		*out = new(bool)
		**out = **in
	}
	if r.Tracing != nil {
		in, out := &r.Tracing, &out.Tracing
		*out = new(bool)
		**out = **in
	}
}

// DeepCopy is a deepcopy function, copying the receiver, creating a new RouterObservabilityConfig.
func (r *RouterObservabilityConfig) DeepCopy() *RouterObservabilityConfig {
	if r == nil {
		return nil
	}
	out := new(RouterObservabilityConfig)
	r.DeepCopyInto(out)
	return out
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Spiffe) DeepCopyInto(out *Spiffe) {
	*out = *in
	if in.IDs != nil {
		in, out := &in.IDs, &out.IDs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is a deepcopy function, copying the receiver, creating a new Spiffe.
func (in *Spiffe) DeepCopy() *Spiffe {
	if in == nil {
		return nil
	}
	out := new(Spiffe)
	in.DeepCopyInto(out)
	return out
}
