<?php

declare(strict_types=1);

namespace Kylesean\Jwt\Tests;

use Hyperf\Context\Context;
use Hyperf\Contract\ConfigInterface;
use Kylesean\Jwt\Contract\ManagerInterface;
use Kylesean\Jwt\Contract\TokenInterface;
use Kylesean\Jwt\Exception\TokenInvalidException;
use Kylesean\Jwt\Middleware\JwtAuthMiddleware;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

#[CoversClass(JwtAuthMiddleware::class)]
class JwtAuthMiddlewareTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected Mockery\MockInterface|ManagerInterface $mockManager;
    protected Mockery\MockInterface|ConfigInterface $mockConfig;
    protected Mockery\MockInterface|ServerRequestInterface $mockRequest;
    protected Mockery\MockInterface|RequestHandlerInterface $mockHandler;
    protected Mockery\MockInterface|ResponseInterface $mockResponse;

    protected function setUp(): void
    {
        parent::setUp();
        // Clear Hyperf Context between tests to avoid state leakage
        Context::destroy(JwtAuthMiddleware::CONTEXT_KEY);

        $this->mockManager = Mockery::mock(ManagerInterface::class);
        $this->mockConfig = Mockery::mock(ConfigInterface::class);
        $this->mockRequest = Mockery::mock(ServerRequestInterface::class);
        $this->mockHandler = Mockery::mock(RequestHandlerInterface::class);
        $this->mockResponse = Mockery::mock(ResponseInterface::class);
    }

    protected function tearDown(): void
    {
        Context::destroy(JwtAuthMiddleware::CONTEXT_KEY);
        parent::tearDown();
    }

    protected function createMiddleware(): JwtAuthMiddleware
    {
        return new JwtAuthMiddleware(
            $this->mockManager,
            $this->mockConfig
        );
    }

    public function testProcessWithValidTokenSetsContextAndAttribute(): void
    {
        $mockToken = Mockery::mock(TokenInterface::class);

        $this->mockManager->shouldReceive('parseTokenFromRequest')
            ->once()
            ->with($this->mockRequest)
            ->andReturn($mockToken);

        // Expect withAttribute to be called, returning a new request
        $modifiedRequest = Mockery::mock(ServerRequestInterface::class);
        $this->mockRequest->shouldReceive('withAttribute')
            ->once()
            ->with(JwtAuthMiddleware::ATTRIBUTE_KEY, $mockToken)
            ->andReturn($modifiedRequest);

        $this->mockHandler->shouldReceive('handle')
            ->once()
            ->with($modifiedRequest)
            ->andReturn($this->mockResponse);

        $middleware = $this->createMiddleware();
        $result = $middleware->process($this->mockRequest, $this->mockHandler);

        $this->assertSame($this->mockResponse, $result);
        // Verify token was stored in Hyperf Context
        $this->assertSame($mockToken, Context::get(JwtAuthMiddleware::CONTEXT_KEY));
    }

    public function testProcessWithNoTokenAndAuthRequiredThrowsException(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token not provided.');

        $this->mockManager->shouldReceive('parseTokenFromRequest')
            ->once()
            ->with($this->mockRequest)
            ->andReturn(null);

        $this->mockConfig->shouldReceive('get')
            ->with('jwt.middleware.auth_required', true)
            ->once()
            ->andReturn(true);

        $middleware = $this->createMiddleware();
        $middleware->process($this->mockRequest, $this->mockHandler);
    }

    public function testProcessWithNoTokenAndAuthNotRequiredContinues(): void
    {
        $this->mockManager->shouldReceive('parseTokenFromRequest')
            ->once()
            ->with($this->mockRequest)
            ->andReturn(null);

        $this->mockConfig->shouldReceive('get')
            ->with('jwt.middleware.auth_required', true)
            ->once()
            ->andReturn(false);

        $this->mockHandler->shouldReceive('handle')
            ->once()
            ->with($this->mockRequest)
            ->andReturn($this->mockResponse);

        $middleware = $this->createMiddleware();
        $result = $middleware->process($this->mockRequest, $this->mockHandler);

        $this->assertSame($this->mockResponse, $result);
        // Context should not have a token
        $this->assertNull(Context::get(JwtAuthMiddleware::CONTEXT_KEY));
    }

    public function testGetTokenStaticMethodReturnsTokenFromContext(): void
    {
        $mockToken = Mockery::mock(TokenInterface::class);
        Context::set(JwtAuthMiddleware::CONTEXT_KEY, $mockToken);

        $this->assertSame($mockToken, JwtAuthMiddleware::getToken());
    }

    public function testGetTokenStaticMethodReturnsNullWhenNoToken(): void
    {
        $this->assertNull(JwtAuthMiddleware::getToken());
    }

    public function testGetSubjectStaticMethodReturnsSubject(): void
    {
        $mockToken = Mockery::mock(TokenInterface::class);
        $mockToken->shouldReceive('getSubject')->once()->andReturn('user_123');
        Context::set(JwtAuthMiddleware::CONTEXT_KEY, $mockToken);

        $this->assertEquals('user_123', JwtAuthMiddleware::getSubject());
    }

    public function testGetSubjectStaticMethodReturnsNullWhenNoToken(): void
    {
        $this->assertNull(JwtAuthMiddleware::getSubject());
    }

    public function testGetClaimStaticMethodReturnsClaim(): void
    {
        $mockToken = Mockery::mock(TokenInterface::class);
        $mockToken->shouldReceive('getClaim')->with('role')->once()->andReturn('admin');
        Context::set(JwtAuthMiddleware::CONTEXT_KEY, $mockToken);

        $this->assertEquals('admin', JwtAuthMiddleware::getClaim('role'));
    }

    public function testGetClaimStaticMethodReturnsNullWhenNoToken(): void
    {
        $this->assertNull(JwtAuthMiddleware::getClaim('role'));
    }
}
