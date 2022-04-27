module github.com/kayrus/smtp-tester

require (
	github.com/emersion/go-sasl v0.0.0-20200509203442-7bfe0ed36a21
	github.com/emersion/go-smtp v0.15.1-0.20211103212524-30169acc42e7
)

// workaround for https://github.com/emersion/go-smtp/pull/148
replace github.com/emersion/go-smtp => github.com/kayrus/go-smtp v0.15.1-0.20211216174341-f5f4e119d8cc

go 1.14
